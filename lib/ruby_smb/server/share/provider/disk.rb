require 'zlib'
require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          TYPE = TYPE_DISK
          class Processor < Processor::Base
            Handle = Struct.new(:remote_path, :local_path, :durable?)
            def initialize(provider, server_client, session)
              super
              @handles = {}
              @query_directory_context = {}
            end

            def maximal_access(path=nil)
              RubySMB::SMB2::BitField::FileAccessMask.new(
                read_attr: 1,
                read_data: 1
              )
            end

            def do_close_smb1(request)
              if (handle = @handles.delete(request.parameter_block.fid)).nil?
                raise NotImplementedError
              end

              response = RubySMB::SMB1::Packet::CloseResponse.new
              response
            end

            def do_close_smb2(request)
              local_path = get_local_path(request.file_id)
              if local_path.nil?
                response = RubySMB::SMB2::Packet::ErrorPacket.new
                response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_FILE_CLOSED
                return response
              end

              @handles.delete(request.file_id.to_binary_s)
              response = RubySMB::SMB2::Packet::CloseResponse.new
              set_common_info(response, local_path)
              response.flags = 1
              response
            end

            def do_create_smb1(request)
              if request.smb_header.flags2.unicode == 1
                raise NotImplementedError
              else
                path = request.data_block.file_name.snapshot[...-1]
              end
              path = path.encode.gsub('\\', File::SEPARATOR)
              local_path = get_local_path(path)
              unless local_path && (local_path.file? || local_path.directory?)
                logger.warn("Requested path does not exist: #{local_path}")
                raise NotImplementedError
              end

              response = SMB1::Packet::NtCreateAndxResponse.new
              block = response.parameter_block
              block.fid = rand(0xffff)
              # fields are slightly different so #set_common_info can't be used :(
              begin
                block.create_time = local_path.birthtime
              rescue NotImplementedError
                logger.warn("The file system does not support #birthtime for #{path}")
              end

              block.last_access_time = local_path.atime
              block.last_write_time = local_path.mtime
              block.last_change_time = local_path.ctime
              if local_path.file?
                block.end_of_file = local_path.size
                block.allocation_size = get_allocation_size(local_path)
              end

              @handles[response.parameter_block.fid] = Handle.new(path, local_path, false)
              response
            end

            def do_create_smb2(request)
              unless request.create_disposition == RubySMB::Dispositions::FILE_OPEN
                logger.warn("Can not handle CREATE request for disposition: #{request.create_disposition}")
                raise NotImplementedError
              end

              # process the delayed io fields
              request.name.read_now!
              unless request.contexts_offset == 0
                request.contexts.read_now!
                request.contexts.each do |context|
                  context.name.read_now!
                  context.data.read_now!
                end
              end

              path = request.name.snapshot
              local_path = get_local_path(path)
              unless local_path && (local_path.file? || local_path.directory?)
                logger.warn("Requested path does not exist: #{local_path}")
                response = RubySMB::SMB2::Packet::ErrorPacket.new
                response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND
                return response
              end

              durable = false
              response = RubySMB::SMB2::Packet::CreateResponse.new
              response.create_action = RubySMB::CreateActions::FILE_OPENED
              set_common_info(response, local_path)
              response.file_id.persistent = Zlib::crc32(path)
              response.file_id.volatile = rand(0xffffffff)

              request.contexts.each do |req_ctx|
                case req_ctx.name
                when SMB2::CreateContext::CREATE_DURABLE_HANDLE
                  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9adbc354-5fad-40e7-9a62-4a4b6c1ff8a0
                  next if request.contexts.any? { |ctx| ctx.name == SMB2::CreateContext::CREATE_DURABLE_HANDLE_RECONNECT }

                  if request.contexts.any? { |ctx| [ SMB2::CreateContext::CREATE_DURABLE_HANDLE_V2, SMB2::CreateContext::CREATE_DURABLE_HANDLE_RECONNECT_v2 ].include?(ctx.name) }
                    response = RubySMB::SMB2::Packet::ErrorPacket.new
                    response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_PARAMETER
                    return response
                  end

                  durable = true
                  res_ctx = SMB2::CreateContext::CreateDurableHandleResponse.new
                when SMB2::CreateContext::CREATE_DURABLE_HANDLE_V2
                  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/33e6800a-adf5-4221-af27-7e089b9e81d1
                  if request.contexts.any? { |ctx| [ SMB2::CreateContext::CREATE_DURABLE_HANDLE, SMB2::CreateContext::CREATE_DURABLE_HANDLE_RECONNECT, SMB2::CreateContext::CREATE_DURABLE_HANDLE_RECONNECT_v2 ].include?(ctx.name) }
                    response = RubySMB::SMB2::Packet::ErrorPacket.new
                    response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_PARAMETER
                    return response
                  end

                  durable = true
                  res_ctx = SMB2::CreateContext::CreateDurableHandleV2Response.new(
                    timeout: 1000,
                    flags: req_ctx.data.flags
                  )
                when SMB2::CreateContext::CREATE_QUERY_MAXIMAL_ACCESS
                  res_ctx = SMB2::CreateContext::CreateQueryMaximalAccessResponse.new(
                    maximal_access: maximal_access(path)
                  )
                when SMB2::CreateContext::CREATE_QUERY_ON_DISK_ID
                  res_ctx = SMB2::CreateContext::CreateQueryOnDiskIdResponse.new(
                    disk_file_id: local_path.stat.ino,
                    volume_id: local_path.stat.dev
                  )
                else
                  logger.warn("Can not handle CREATE context: #{req_ctx.name}")
                  next
                end

                response.contexts << SMB2::CreateContext::CreateContextResponse.new(name: res_ctx.class::NAME, data: res_ctx)
              end

              if response.contexts.length > 0
                # fixup the offsets
                response.contexts[0...-1].each do |ctx|
                  ctx.next_offset = ctx.num_bytes
                end
                response.contexts[-1].next_offset = 0
                response.contexts_offset = response.buffer.abs_offset
                response.contexts_length = response.buffer.num_bytes
              else
                response.contexts_offset = 0
                response.contexts_length = 0
              end

              @handles[response.file_id.to_binary_s] = Handle.new(path, local_path, durable)
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
                # probe #build_info to see if it supports the requested info class
                build_info(Pathname.new(__FILE__), info_class)
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

                info = build_info(dirent, info_class, rename: dirent_name)
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

            def do_read_smb1(request)
              local_path = get_local_path(request.parameter_block.fid)

              if local_path.nil?
                raise NotImplementedError
              end

              buffer = nil
              local_path.open do |file|
                file.seek(request.parameter_block.offset.snapshot)
                buffer = file.read(request.parameter_block.remaining.snapshot)
              end

              # minimum bytes is ignored when reading from a file
              # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/7e6c7cc2-c3f1-4335-8263-d7412f77140e
              if buffer.nil? || buffer.length == 0
                raise NotImplementedError
              end

              response = SMB1::Packet::ReadAndxResponse.new
              response.parameter_block.data_length = buffer.length
              response.data_block.data = buffer
              response
            end

            def do_read_smb2(request)
              local_path = get_local_path(request.file_id)
              if local_path.nil?
                response = RubySMB::SMB2::Packet::ErrorPacket.new
                response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_FILE_CLOSED
                return response
              end

              raise NotImplementedError unless request.channel == SMB2::SMB2_CHANNEL_NONE

              buffer = nil
              local_path.open do |file|
                file.seek(request.offset.snapshot)
                buffer = file.read(request.read_length)
              end

              # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/21e8b343-34e9-4fca-8d93-03dd2d3e961e
              if buffer.nil? || buffer.length == 0 || buffer.length < request.min_bytes
                response = SMB2::Packet::ErrorPacket.new
                response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_END_OF_FILE
                return response
              end

              response = SMB2::Packet::ReadResponse.new
              response.data_length = buffer.length
              response.buffer = buffer
              response
            end

            private

            def build_file_attributes(path)
              file_attributes = Fscc::FileAttributes.new
              if path.file?
                file_attributes.normal = 1
              elsif path.directory?
                file_attributes.directory = 1
              end
              file_attributes
            end

            def build_info(path, info_class, rename: nil)
              case info_class
              when Fscc::FileInformation::FILE_ID_BOTH_DIRECTORY_INFORMATION
                info = Fscc::FileInformation::FileIdBothDirectoryInformation.new
                set_common_info(info, path)
                info.file_name = rename || path.basename.to_s
              when Fscc::FileInformation::FILE_FULL_DIRECTORY_INFORMATION
                info = Fscc::FileInformation::FileFullDirectoryInformation.new
                set_common_info(info, path)
                info.file_name = rename || path.basename.to_s
              else
                raise NotImplementedError, "unsupported info class: #{info_class}"
              end

              align = 8
              info.next_offset = info.num_bytes + ((align - info.num_bytes % align) % align)
              info
            end

            def get_allocation_size(path)
              (path.size + (4095 - (path.size + 4095) % 4096))
            end

            def get_local_path(path)
              case path
              # SMB1 uses uint16_t file IDs
              when ::BinData::Uint16le
                local_path = @handles[path]&.local_path
              # SMB2 uses a compound field for file IDs, so convert it to the binary rep and use that as the key
              when Field::Smb2Fileid
                local_path = @handles[path.to_binary_s]&.local_path
              when ::String
                path = path.encode.gsub('\\', File::SEPARATOR)
                local_path = (provider.path + path.encode).cleanpath
                # TODO: report / handle directory traversal issues more robustly
                raise RuntimeError unless local_path == provider.path || local_path.to_s.start_with?(provider.path.to_s + '/')
              else
                raise NotImplementedError, "Can not get the local path for: #{path.inspect}"
              end

              local_path
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

            # A bunch of structures have these common fields with the same meaning, so set them all here
            def set_common_info(info, path)
              begin
                info.create_time = path.birthtime
              rescue NotImplementedError
                logger.warn("The file system does not support #birthtime for #{path}")
              end

              info.last_access = path.atime
              info.last_write = path.mtime
              info.last_change = path.ctime
              if path.file?
                info.end_of_file = path.size
                info.allocation_size = get_allocation_size(path)
              end
              info.file_attributes = build_file_attributes(path)
            end

            # Turn a wildcard expression into a regex. Not all wildcard
            # characters are supported. Wildcards that can not be converted will
            # raise a NotImplementedError.
            #
            # @param [String] wildcard The wildcard expression to convert.
            # @return [Regexp] The converted expression.
            # @raise [NotImplementedError] Raised when the wildcard can not be
            #   converted.
            def wildcard_to_regex(wildcard)
              return Regexp.new('.*') if ['*.*', ''].include?(wildcard)

              if wildcard.each_char.any? { |c| c == '<' || c == '>' }
                # the < > wildcard operators are not supported
                raise NotImplementedError
              end

              wildcard = Regexp.escape(wildcard)
              wildcard = wildcard.gsub(/(\\\?)+$/) { |match| ".{0,#{match.length / 2}}"}
              wildcard = wildcard.gsub('\?', '.')
              wildcard = wildcard.gsub('\*', '.*')
              wildcard = wildcard.gsub('"', '\.')
              Regexp.new('^' + wildcard + '$')
            end
          end

          def initialize(name, path)
            path = Pathname.new(File.expand_path(path))
            raise ArgumentError unless path.directory?
            @path = path
            super(name)
          end

          attr_accessor :path
        end
      end
    end
  end
end
