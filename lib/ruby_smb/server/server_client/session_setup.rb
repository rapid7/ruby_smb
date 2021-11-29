module RubySMB
  class Server
    class ServerClient
      module SessionSetup
        #
        # Setup a new session based on the negotiated dialect. Once session setup is complete, the state will be updated
        # to :authenticated.
        #
        # @param [String] raw_request the session setup request to process
        def handle_session_setup(raw_request)
          response = nil

          case metadialect.order
          when Dialect::ORDER_SMB1
            request = SMB1::Packet::SessionSetupRequest.read(raw_request)
            response = do_session_setup_smb1(request)
          when Dialect::ORDER_SMB2
            request = SMB2::Packet::SessionSetupRequest.read(raw_request)
            response = do_session_setup_smb2(request)
          end

          if response.nil?
            disconnect!
          else
            send_packet(response)
          end

          nil
        end

        def do_session_setup_smb1(request)
          gss_result = process_gss(request.data_block.security_blob)
          return if gss_result.nil?

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

          if gss_result.nt_status == WindowsError::NTStatus::STATUS_SUCCESS
            @state = :authenticated
            @identity = gss_result.identity
          end

          response
        end

        def do_session_setup_smb2(request)
          gss_result = process_gss(request.buffer)
          return if gss_result.nil?

          response = SMB2::Packet::SessionSetupResponse.new
          response.smb2_header.nt_status = gss_result.nt_status.value
          response.smb2_header.credits = 1
          response.smb2_header.message_id = request.smb2_header.message_id
          response.smb2_header.session_id = @session_id = @session_id || SecureRandom.random_bytes(4).unpack1('V')
          response.buffer = gss_result.buffer

          update_preauth_hash(request) if @dialect == '0x0311'
          if gss_result.nt_status == WindowsError::NTStatus::STATUS_SUCCESS
            response.smb2_header.credits = 32
            @state = :authenticated
            @identity = gss_result.identity
            @session_key = @gss_authenticator.session_key
          elsif gss_result.nt_status == WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED && @dialect == '0x0311'
            update_preauth_hash(response)
          end

          response
        end

        def do_logoff_smb2(request)
          @state = :session_setup
          @session_id = nil
          @session_key = nil
          @identity = nil

          response = SMB2::Packet::LogoffResponse.new
          response
        end
      end
    end
  end
end

