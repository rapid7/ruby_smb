require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          class Processor < Provider::Processor::Base
            module Read
              def do_read_andx_smb1(request)
                # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/bb8fcb6a-3032-46a1-ad4a-c0d7892921f9
                handle = @handles[request.parameter_block.fid]

                if handle.nil?
                  response = SMB1::Packet::EmptyPacket.new
                  response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE
                end

                handle.file.seek(request.parameter_block.offset.snapshot)
                buffer = handle.file.read(request.parameter_block.max_count_of_bytes_to_return.snapshot)

                response = SMB1::Packet::ReadAndxResponse.new
                response.parameter_block.available = 0xffff  # this field is only used for named pipes, must be -1 for all others
                unless buffer.nil?
                  response.parameter_block.data_length = buffer.length
                  response.parameter_block.data_offset = response.data_block.data.abs_offset
                  response.data_block.data = buffer
                end
                response
              end

              def do_read_smb2(request)
                handle = @handles[request.file_id.to_binary_s]
                if handle.nil?
                  response = RubySMB::SMB2::Packet::ErrorPacket.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_FILE_CLOSED
                  return response
                end

                raise NotImplementedError unless request.channel == SMB2::SMB2_CHANNEL_NONE

                handle.file.seek(request.offset.snapshot)
                buffer = handle.file.read(request.read_length)

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
            end
          end
        end
      end
    end
  end
end
