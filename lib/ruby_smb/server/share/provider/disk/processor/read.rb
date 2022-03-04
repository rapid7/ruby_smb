require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          class Processor < Provider::Processor::Base
            module Read
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
            end
          end
        end
      end
    end
  end
end
