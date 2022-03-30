require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          class Processor < Provider::Processor::Base
            module Query
              def do_transactions2_smb1(request)
                # can't find an example where more than one setup is set, this code makes alot of assumptions that there
                # are exactly 0 or 1 entries
                if request.parameter_block.setup.length > 1
                  raise NotImplementedError, 'There are more than 1 TRANSACTION2 setup values'
                end

                case request.data_block.trans2_parameters
                when SMB1::Packet::Trans2::FindFirst2RequestTrans2Parameters
                  response = transaction2_smb1_find_first2(request)
                when SMB1::Packet::Trans2::QueryFileInformationRequestTrans2Parameters
                  response = transaction2_smb1_query_file_information(request)
                when SMB1::Packet::Trans2::QueryPathInformationRequestTrans2Parameters
                  response = transaction2_smb1_query_path_information(request)
                when SMB1::Packet::Trans2::QueryFsInformationRequestTrans2Parameters
                  response = transaction2_smb1_query_fs_information(request)
                else
                  subcommand = request.parameter_block.setup.first
                  if subcommand
                    logger.warn("Can not handle TRANSACTION2 request for subcommand #{subcommand} (#{SMB1::Packet::Trans2::Subcommands.name(subcommand)})")
                  else
                    logger.warn('Can not handle TRANSACTION2 request with missing subcommand')
                  end
                  raise NotImplementedError
                end

                if response and response.parameter_block.is_a?(RubySMB::SMB1::Packet::Trans2::Response::ParameterBlock)
                  response.parameter_block.setup = []
                  response.parameter_block.total_parameter_count = response.parameter_block.parameter_count = response.data_block.trans2_parameters.num_bytes
                  response.parameter_block.total_data_count = response.parameter_block.data_count = response.data_block.trans2_data.num_bytes
                end

                response
              end

              def do_query_directory_smb2(request)
                local_path = get_local_path(request.file_id)
                if local_path.nil?
                  response = RubySMB::SMB2::Packet::ErrorPacket.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_FILE_CLOSED
                  return response
                end

                # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/29dfcc9b-3aec-406b-abb5-0b4fe96712e2
                info_class = request.file_information_class.snapshot
                begin
                  # probe #build_fscc_file_information to see if it supports the requested info class
                  build_fscc_file_information(Pathname.new(__FILE__), info_class)
                rescue NotImplementedError
                  logger.warn("Can not handle QUERY_DIRECTORY request for class: #{info_class}")
                  raise
                end

                unless local_path.directory?
                  response = SMB2::Packet::ErrorPacket.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_PARAMETER
                  return response
                end

                search_pattern = request.name.snapshot.dup.encode
                begin
                  search_regex = wildcard_to_regex(search_pattern)
                rescue NotImplementedError
                  logger.warn("Can not handle QUERY_DIRECTORY wildcard pattern: #{search_pattern}")
                  raise
                end

                return_single = request.flags.return_single == 1

                align = 8
                infos = []
                total_size = 0

                if @query_directory_context[request.file_id.to_binary_s].nil? || request.flags.reopen == 1 || request.flags.restart_scans == 1
                  dirents = local_path.children.sort.to_a
                  dirents.unshift(local_path.parent) unless local_path.parent == local_path
                  dirents.unshift(local_path)
                  @query_directory_context[request.file_id.to_binary_s] = dirents
                else
                  dirents = @query_directory_context[request.file_id.to_binary_s]
                end

                consume_dirents(local_path, dirents, filter_regex: search_regex) do |dirent, dirent_name|
                  info = build_fscc_file_information(dirent, info_class, rename: dirent_name)
                  info_size = info.num_bytes + ((align - info.num_bytes % align) % align)
                  if total_size + info_size > request.output_length
                    dirents.unshift(dirent) # no space left for this one so put it back
                    break
                  end

                  infos << info
                  total_size += info_size
                  break if return_single
                end

                if infos.length == 0
                  response = SMB2::Packet::QueryDirectoryResponse.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NO_MORE_FILES
                  return response
                end

                response = SMB2::Packet::QueryDirectoryResponse.new
                infos.last.next_offset = 0 if infos.last
                buffer = ""
                infos.each do |info|
                  info = info.to_binary_s
                  buffer << info + "\x00".b * ((align - info.length % align) % align)
                end
                response.buffer = buffer
                response
              end

              def do_query_info_smb2(request)
                local_path = get_local_path(request.file_id)
                if local_path.nil?
                  response = RubySMB::SMB2::Packet::ErrorPacket.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_FILE_CLOSED
                  return response
                end

                case request.info_type
                when SMB2::SMB2_INFO_FILE
                  info = query_info_smb2_file(request, local_path)
                when SMB2::SMB2_INFO_FILESYSTEM
                  info = query_info_smb2_filesystem(request, local_path)
                else
                  logger.warn("Can not handle QUERY_INFO request for type: #{request.info_type}, class: #{request.file_information_class}")
                  raise NotImplementedError
                end

                response = SMB2::Packet::QueryInfoResponse.new
                response.buffer = info.to_binary_s
                response
              end

              private

              # This function iterates over dirents, filtering out entries as necessary. It relies on the fact that
              # dirents is a mutable object.
              #
              # @param Pathmame local_path a path to use for relative location checks
              # @param [Array<Pathname>] dirents the array of dirents to iterate over
              # @param Regex filter_regex a regex that when specified will be used to filter out entries that don't match
              def consume_dirents(local_path, dirents, filter_regex: nil)
                until dirents.empty?
                  dirent = dirents.shift
                  next unless dirent.file? || dirent.directory? # filter out everything but files and directories

                  case dirent
                  when local_path
                    dirent_name = '.'
                  when local_path.parent
                    dirent_name = '..'
                  else
                    dirent_name = dirent.basename.to_s
                  end
                  next unless filter_regex.nil? || filter_regex.match?(dirent_name)

                  yield dirent, dirent_name
                end
              end

              def transaction2_smb1_find_first2(request)
                # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/f93455dc-2bd7-4698-b91e-8c9c7abd63cf
                raise ArgumentError unless request.data_block.trans2_parameters.is_a? SMB1::Packet::Trans2::FindFirst2RequestTrans2Parameters

                subdir, _, search_pattern = request.data_block.trans2_parameters.filename.encode.gsub('\\', File::SEPARATOR).rpartition(File::SEPARATOR)
                local_path = get_local_path(subdir)
                unless local_path.directory?
                  response = SMB1::Packet::EmptyPacket.new
                  response.smb_header.nt_status = WindowsError::NTStatus::STATUS_NO_SUCH_FILE
                  return response
                end

                begin
                  search_regex = wildcard_to_regex(search_pattern)
                rescue NotImplementedError
                  logger.warn("Can not handle TRANSACTION2 FIND_FIRST2 wildcard pattern: #{search_pattern}")
                  raise
                end

                # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/29dfcc9b-3aec-406b-abb5-0b4fe96712e2
                info_level = request.data_block.trans2_parameters.information_level.to_i
                if info_level == SMB1::Packet::Trans2::FindInformationLevel::SMB_FIND_FILE_FULL_DIRECTORY_INFO
                  info_class = SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo
                elsif info_level == SMB1::Packet::Trans2::FindInformationLevel::SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                  info_class = SMB1::Packet::Trans2::FindInformationLevel::FindFileBothDirectoryInfo
                else
                  logger.warn("Can not handle TRANSACTION2 FIND_FIRST2 request for class: #{info_level} (#{SMB1::Packet::Trans2::FindInformationLevel.name(info_level)})")
                  raise NotImplementedError
                end

                logger.debug("Handling TRANSACTION2 FIND_FIRST2 request for class: #{info_level} (#{SMB1::Packet::Trans2::FindInformationLevel.name(info_level)})")
                infos = []
                dirents = local_path.children.sort.to_a

                consume_dirents(local_path, dirents, filter_regex: search_regex) do |dirent, dirent_name|
                  info = info_class.new
                  info.unicode = request.smb_header.flags2.unicode == 1
                  set_common_timestamps(info, dirent)
                  info.end_of_file = dirent.size
                  info.allocation_size = get_allocation_size(dirent)
                  info.ext_file_attributes.directory = dirent.directory? ? 1 : 0
                  info.ext_file_attributes.read_only = !dirent.writable? ? 1 : 0
                  info.ext_file_attributes.normal = (dirent.file? && dirent.writable?) ? 1 : 0
                  info.file_name = dirent_name
                  info.next_offset = info.num_bytes
                  infos << info
                end
                infos.last.next_offset = 0 unless infos.empty?

                response = SMB1::Packet::Trans2::FindFirst2Response.new
                response.smb_header.flags2.unicode = request.smb_header.flags2.unicode == 1
                if infos.empty?
                  response.smb_header.nt_status = WindowsError::NTStatus::STATUS_NO_SUCH_FILE
                else
                  buffer = infos.map(&:to_binary_s).join
                  response.data_block.trans2_parameters.sid = rand(0xffff)
                  response.data_block.trans2_parameters.search_count = infos.length
                  response.data_block.trans2_parameters.eos = 1
                  response.data_block.trans2_data.buffer = buffer
                end
                response
              end

              def transaction2_smb1_query_information(request, response, local_path)
                unless local_path&.exist?
                  response = SMB1::Packet::EmptyPacket.new
                  response.smb_header.nt_status = WindowsError::NTStatus::STATUS_NO_SUCH_FILE
                  return response
                end

                case request.data_block.trans2_parameters.information_level
                when SMB1::Packet::Trans2::QueryInformationLevel::SMB_QUERY_FILE_BASIC_INFO
                  info = SMB1::Packet::Trans2::QueryInformationLevel::QueryFileBasicInfo.new
                  set_common_timestamps(info, local_path)
                  info.ext_file_attributes.directory = local_path.directory? ? 1 : 0
                  info.ext_file_attributes.read_only = !local_path.writable? ? 1 : 0
                  info.ext_file_attributes.normal = (local_path.file? && local_path.writable?) ? 1 : 0
                when SMB1::Packet::Trans2::QueryInformationLevel::SMB_QUERY_FILE_STANDARD_INFO
                  info = SMB1::Packet::Trans2::QueryInformationLevel::QueryFileStandardInfo.new
                  info.end_of_file = local_path.size
                  info.allocation_size = get_allocation_size(local_path)
                  info.directory = local_path.directory? ? 1 : 0
                else
                  level = request.data_block.trans2_parameters.information_level
                  logger.warn("Can not handle TRANSACTION2 QUERY request for information level #{level} (#{SMB1::Packet::Trans2::QueryInformationLevel.name(level)})")
                  raise NotImplementedError
                end

                response.data_block.trans2_data.buffer = info.to_binary_s
                response
              end

              def transaction2_smb1_query_file_information(request)
                # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/0a96fae0-b183-42b6-92bd-e05b1d92f434
                raise ArgumentError unless request.data_block.trans2_parameters.is_a? SMB1::Packet::Trans2::QueryFileInformationRequestTrans2Parameters

                local_path = get_local_path(request.data_block.trans2_parameters.fid)
                response = SMB1::Packet::Trans2::QueryFileInformationResponse.new
                transaction2_smb1_query_information(request, response, local_path)
              end

              def transaction2_smb1_query_fs_information(request)
                # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/c396398f-2d7f-4356-bac4-326076bafcd1
                raise ArgumentError unless request.data_block.trans2_parameters.is_a? SMB1::Packet::Trans2::QueryFsInformationRequestTrans2Parameters

                local_path = provider.path
                unless local_path&.exist?
                  response = SMB1::Packet::EmptyPacket.new
                  response.smb_header.nt_status = WindowsError::NTStatus::STATUS_NO_SUCH_FILE
                  return response
                end

                response = SMB1::Packet::Trans2::QueryFsInformationResponse.new

                case request.data_block.trans2_parameters.information_level
                when SMB1::Packet::Trans2::QueryFsInformationLevel::SMB_QUERY_FS_ATTRIBUTE_INFO
                  info = SMB1::Packet::Trans2::QueryFsInformationLevel::QueryFsAttributeInfo.new
                  info.flags.file_case_sensitive_search = 1
                  info.flags.file_case_preserved_names = 1
                  info.flags.file_unicode_on_disk = 1
                else
                  level = request.data_block.trans2_parameters.information_level
                  logger.warn("Can not handle TRANSACTION2 QUERY_FS request for information level #{level} (#{SMB1::Packet::Trans2::QueryFsInformationLevel.name(level)})")
                  raise NotImplementedError
                end

                response.data_block.trans2_data.buffer = info.to_binary_s
                response
              end

              def transaction2_smb1_query_path_information(request)
                # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/a5941db4-b992-442a-ba81-fe3378c5bd60
                raise ArgumentError unless request.data_block.trans2_parameters.is_a? SMB1::Packet::Trans2::QueryPathInformationRequestTrans2Parameters

                local_path = get_local_path(request.data_block.trans2_parameters.filename.encode)
                response = SMB1::Packet::Trans2::QueryPathInformationResponse.new
                transaction2_smb1_query_information(request, response, local_path)
              end

              def query_info_smb2_file(request, local_path)
                raise ArgumentError unless request.info_type == SMB2::SMB2_INFO_FILE

                case request.file_information_class
                when Fscc::FileInformation::FILE_NORMALIZED_NAME_INFORMATION
                  info = Fscc::FileInformation::FileNameInformation.new(file_name: @handles[request.file_id.to_binary_s].remote_path)
                else
                  info = build_fscc_file_information(local_path, request.file_information_class)
                end

                info
              end

              def query_info_smb2_filesystem(request, local_path)
                raise ArgumentError unless request.info_type == SMB2::SMB2_INFO_FILESYSTEM

                case request.file_information_class
                when Fscc::FileSystemInformation::FILE_FS_ATTRIBUTE_INFORMATION
                  # emulate NTFS just like Samba does
                  info = Fscc::FileSystemInformation::FileFsAttributeInformation.new(
                    file_system_attributes: {
                      file_case_sensitive_search: 1,
                      file_case_preserved_names: 1,
                      file_unicode_on_disk: 1,
                      file_supports_object_ids: 1,
                    },
                    maximum_component_name_length: 255,
                    file_system_name: 'NTFS'
                  )
                when Fscc::FileSystemInformation::FILE_FS_VOLUME_INFORMATION
                  info = Fscc::FileSystemInformation::FileFsVolumeInformation.new(
                    volume_serial_number: provider.path.stat.ino,
                    volume_label: provider.name
                  )
                else
                  logger.warn("Can not handle QUERY_INFO request for type: #{request.info_type}, class: #{request.file_information_class}")
                  raise NotImplementedError
                end

                info
              end
            end
          end
        end
      end
    end
  end
end
