require 'zlib'
require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          TYPE = TYPE_DISK
          class Processor < Processor::Base
            def initialize(provider, server_client)
              super
              @handle_guids = {}  # TODO: update this to a more robust object
            end

            def maximal_access(path=nil)
              RubySMB::SMB2::BitField::FileAccessMask.read([0x00000081].pack('V'))
            end

            def do_close_smb2(request)
              local_path = get_local_path(request.file_id)
              @handle_guids.delete(request.file_id.to_binary_s)
              response = RubySMB::SMB2::Packet::CloseResponse.new
              set_common_info(response, local_path)
              response.flags = 1
              response.structure_size = 0x3c
              response
            end

            def do_create_smb2(request)
              path = request.name.snapshot.dup
              path = path.encode.gsub('\\', File::SEPARATOR)
              local_path = get_local_path(path)

              response = RubySMB::SMB2::Packet::CreateResponse.new
              response.create_action = 1
              set_common_info(response, local_path)
              response.file_id.persistent = Zlib::crc32(path)
              response.file_id.volatile = rand(0xffffffff)
              @handle_guids[response.file_id.to_binary_s] = path

              request.contexts.each do |req_ctx|
                case req_ctx.name
                when SMB2::CreateContext::CREATE_QUERY_MAXIMAL_ACCESS
                  res_ctx = SMB2::CreateContext::CreateQueryMaximalAccessResponse.new(
                    maximal_access: maximal_access(path)
                  )
                when SMB2::CreateContext::CREATE_QUERY_ON_DISK_ID
                  res_ctx = SMB2::CreateContext::CreateQueryOnDiskIdResponse.new
                else
                  logger.warn("No handler for context message: #{req_ctx.name}")
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

              response
            end

            def do_query_directory_smb2(request)
              local_path = get_local_path(request.file_id)
              search_pattern = request.name.snapshot
              # TODO: need to assert that the info level is 37 SMB2_FIND_ID_BOTH_DIRECTORY_INFO
              infos = [
                build_info(local_path, rename: '.'),
                build_info(local_path, rename: '..') # don't leak parent directory info
              ]
              response = SMB2::Packet::QueryDirectoryResponse.new
              local_path.children.each do |child|
                next unless child.file? || child.directory? # filter out everything but files and directories
                next if child.basename.to_s.start_with?('.') # TODO: remove stop filtering out hidden entries
                infos << build_info(child)
              end

              infos.last.next_offset = 0 if infos.last
              buffer = ""
              infos.each do |info|
                info = info.to_binary_s
                buffer << info + ("\x00".b * (7 - (info.length + 7) % 8))
              end
              response.buffer = buffer

              # TODO: figure out the proper way to buffer and send multiple responses as necessary
              response.smb2_header.credits = request.smb2_header.credits
              response.smb2_header.message_id = request.smb2_header.message_id
              response.smb2_header.session_id = request.smb2_header.session_id
              response.smb2_header.tree_id = request.smb2_header.tree_id
              @server_client.send_packet(response)

              chained_response = SMB2::Packet::QueryDirectoryResponse.new
              chained_response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NO_MORE_FILES
              chained_response.smb2_header.message_id = request.smb2_header.message_id + 1
              chained_response
            end

            def do_query_info_smb2(request)
              raise NotImplementedError unless request.info_type == 1 && request.file_information_class == 34

              local_path = get_local_path(request.file_id)
              response = SMB2::Packet::QueryInfoResponse.new
              info = Fscc::FileInformation::FileNetworkOpenInformation.new
              set_common_info(info, local_path)
              response.buffer = info.to_binary_s
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

            def build_info(path, rename: nil)
              info = Fscc::FileInformation::FileIdBothDirectoryInformation.new
              set_common_info(info, path)
              info.file_name = rename || path.basename.to_s
              info.next_offset = (info.num_bytes + (7 - (info.num_bytes + 7) % 8))
              info
            end

            def get_local_path(path)
              case path
              when Field::Smb2Fileid
                path = @handle_guids[path.to_binary_s]
              when ::String
                path = path.encode
              else
                raise NotImplementedError, "Can not get the local path for: #{path.inspect}"
              end

              local_path = Pathname.new(provider.path + '/' + path).cleanpath
              # TODO: report / handle directory traversal issues more robustly
              raise RuntimeError unless local_path.to_s == provider.path || local_path.to_s.start_with?(provider.path + '/')
              local_path
            end

            # A bunch of structures have these common fields with the same meaning, so set them all here
            def set_common_info(info, path)
              info.create_time = path.birthtime  # TODO: #birthtime will raise NotImplementedError on some file systems
              info.last_access = path.atime
              info.last_write = path.mtime
              info.last_change = path.ctime
              if path.file?
                info.end_of_file = path.size
                info.allocation_size = (path.size + (4095 - (path.size + 4095) % 4096))
              end
              info.file_attributes = build_file_attributes(path)
            end
          end

          def initialize(name, path)
            @path = File.expand_path(path)
            super(name)
          end

          attr_accessor :path
        end
      end
    end
  end
end
