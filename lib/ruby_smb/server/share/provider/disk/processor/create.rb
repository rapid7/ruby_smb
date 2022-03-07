require 'zlib'
require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          class Processor < Provider::Processor::Base
            module Create
              def do_nt_create_andx_smb1(request)
                path = request.data_block.file_name.snapshot[...-1]
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
            end
          end
        end
      end
    end
  end
end
