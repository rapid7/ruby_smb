require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          class Processor < Provider::Processor::Base
            module Query
              def do_transactions2_smb1(request)
                # can't find an example where more than one setup is set, this code makes alot of assumptions there are exactly 0 or 1 entries
                raise NotImplementedError if request.parameter_block.setup.length > 1

                case request.data_block.trans2_parameters
                when SMB1::Packet::Trans2::QueryFileInformationRequestTrans2Parameters
                  response = transaction2_smb1_query_file_information(request)
                else
                  raise NotImplementedError
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

                while dirents.length > 0
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
                  next unless search_regex.match?(dirent_name)

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

              def transaction2_smb1_query_file_information(request)
                raise ArgumentError unless request.data_block.trans2_parameters.is_a? SMB1::Packet::Trans2::QueryFileInformationRequestTrans2Parameters

                local_path = get_local_path(request.data_block.trans2_parameters.fid)
                raise NotImplementedError if local_path.nil?

                response = RubySMB::SMB1::Packet::Trans2::QueryFileInformationResponse.new
                case request.data_block.trans2_parameters.information_level
                when SMB1::Packet::QueryInfo::SMB_QUERY_FILE_BASIC_INFO
                  resp_info = SMB1::Packet::QueryInfo::SmbQueryFileBasicInfo.new
                  set_common_timestamps(resp_info, local_path)
                  resp_info.ext_file_attributes.directory = local_path.directory? ? 1 : 0
                  resp_info.ext_file_attributes.read_only = !local_path.writable? ? 1 : 0
                  resp_info.ext_file_attributes.normal = (local_path.file? && local_path.writeable?) ? 1 : 0
                when SMB1::Packet::QueryInfo::SMB_QUERY_FILE_STANDARD_INFO
                  resp_info = SMB1::Packet::QueryInfo::SmbQueryFileStandardInfo.new
                  resp_info.end_of_file = local_path.size
                  resp_info.allocation_size = get_allocation_size(local_path)
                  resp_info.directory = local_path.directory? ? 1 : 0
                else
                  raise NotImplementedError
                end

                response.parameter_block.total_parameter_count = response.parameter_block.parameter_count = request.parameter_block.setup.length * 2 # x2 because it's the byte count
                response.parameter_block.total_data_count = response.parameter_block.data_count = resp_info.num_bytes
                response.data_block.trans2_data = resp_info.to_binary_s
                response
              end

              def query_info_smb2_file(request, local_path)
                raise ArgumentError unless request.info_type == SMB2::SMB2_INFO_FILE

                case request.file_information_class
                when Fscc::FileInformation::FILE_EA_INFORMATION
                  info = Fscc::FileInformation::FileEaInformation.new
                when Fscc::FileInformation::FILE_NETWORK_OPEN_INFORMATION
                  info = Fscc::FileInformation::FileNetworkOpenInformation.new
                  set_common_info(info, local_path)
                when Fscc::FileInformation::FILE_NORMALIZED_NAME_INFORMATION
                  info = Fscc::FileInformation::FileNameInformation.new(file_name: @handles[request.file_id.to_binary_s].remote_path)
                when Fscc::FileInformation::FILE_STREAM_INFORMATION
                  raise NotImplementedError unless local_path.file?

                  info = Fscc::FileInformation::FileStreamInformation.new(
                    stream_size: local_path.size,
                    stream_allocation_size: get_allocation_size(local_path),
                    stream_name: '::$DATA'
                  )
                else
                  logger.warn("Can not handle QUERY_INFO request for type: #{request.info_type}, class: #{request.file_information_class}")
                  raise NotImplementedError
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
