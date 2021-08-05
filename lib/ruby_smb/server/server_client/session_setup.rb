module RubySMB
  class Server
    class ServerClient
      module SessionSetup
        def handle_session_setup(raw_request)
          case metadialect.order
          when Dialect::ORDER_SMB1
            handle_session_setup_smb1(raw_request)
          when Dialect::ORDER_SMB2
            handle_session_setup_smb2(raw_request)
          end
        end

        def handle_session_setup_smb1(raw_request)
          request = SMB1::Packet::SessionSetupRequest.read(raw_request)

          gss_result = process_gss(request.data_block.security_blob)
          if gss_result.nil?
            disconnect!
            return
          end

          response = SMB1::Packet::SessionSetupResponse.new
          response.smb_header.pid_low = request.smb_header.pid_low
          response.smb_header.uid = rand(0x10000)
          response.smb_header.mid = request.smb_header.mid
          response.smb_header.nt_status = gss_result.nt_status.value
          response.smb_header.flags.reply = true
          response.smb_header.flags2.unicode = true
          response.smb_header.flags2.extended_security = true
          unless gss_result.buffer.nil?
            response.parameter_block.security_blob_length = gss_result.buffer.length
            response.data_block.security_blob = gss_result.buffer
          end

          send_packet(response)
          if gss_result.nt_status == WindowsError::NTStatus::STATUS_SUCCESS
            @state = :authenticated
            @identity = gss_result.identity
          end
        end

        def handle_session_setup_smb2(raw_request)
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
          response.buffer = gss_result.buffer

          update_preauth_hash(request) if @dialect == '0x0311'
          send_packet(response)
          if gss_result.nt_status == WindowsError::NTStatus::STATUS_SUCCESS
            @state = :authenticated
            @identity = gss_result.identity
          elsif @dialect == '0x0311'
            update_preauth_hash(response)
          end
        end
      end
    end
  end
end

