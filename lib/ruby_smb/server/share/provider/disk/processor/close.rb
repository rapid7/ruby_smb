require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          class Processor < Provider::Processor::Base
            module Close
              def do_close_smb1(request)
                # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/99b767e2-8f0e-438b-ace5-4323940f2dc8
                handle = @handles.delete(request.parameter_block.fid)
                if handle.nil?
                  response = RubySMB::SMB1::Packet::EmptyPacket.new
                  response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE
                  return response
                end

                handle.file.close if handle.file

                response = RubySMB::SMB1::Packet::CloseResponse.new
                response
              end

              def do_close_smb2(request)
                handle = @handles.delete(request.file_id.to_binary_s)
                if handle.nil?
                  response = RubySMB::SMB2::Packet::ErrorPacket.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_FILE_CLOSED
                  return response
                end

                handle.file.close if handle.file

                response = RubySMB::SMB2::Packet::CloseResponse.new
                set_common_info(response, handle.local_path)
                response.flags = 1
                response
              end
            end
          end
        end
      end
    end
  end
end
