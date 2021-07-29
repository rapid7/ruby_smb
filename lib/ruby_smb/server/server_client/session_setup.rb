module RubySMB
  class Server
    class ServerClient
      module SessionSetup
        def handle_session_setup(raw_request)
          request = SMB2::Packet::SessionSetupRequest.read(raw_request)

          gss_result = process_gss(request.buffer)
          if gss_result.nil?
            disconnect!
            return
          end

          response = SMB2::Packet::SessionSetupResponse.new
          response.smb2_header.nt_status = gss_result.nt_status.value
          response.smb2_header.credits = 1
          response.smb2_header.message_id = @message_id += 1
          response.smb2_header.session_id = @session_id = @session_id || SecureRandom.random_bytes(4).unpack1('V')
          response.buffer = gss_result.buffer unless gss_result.nil?
          send_packet(response)
          @state = :authenticated if gss_result.nt_status == WindowsError::NTStatus::STATUS_SUCCESS
        end
      end
    end
  end
end

