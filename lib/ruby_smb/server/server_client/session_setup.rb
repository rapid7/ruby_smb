module RubySMB
  class Server
    class ServerClient
      module SessionSetup
        def do_session_setup_andx_smb1(request, session)
          session_id = request.smb_header.uid
          if session_id == 0
            session_id = rand(1..0x10000)
            session = @session_table[session_id] = Server::Session.new(session_id)
          else
            session = @session_table[session_id]
            if session.nil?
              response = SMB1::Packet::EmptyPacket.new
              response.smb_header.nt_status = SMBError::STATUS_SMB_BAD_UID
              return response
            end
          end

          gss_result = process_gss(request.data_block.security_blob)
          return if gss_result.nil?

          response = SMB1::Packet::SessionSetupResponse.new
          response.smb_header.pid_low = request.smb_header.pid_low
          response.smb_header.uid = session_id
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
            session.state = :valid
            session.user_id = gss_result.identity
            session.key = @gss_authenticator.session_key
          end

          response
        end

        alias :do_session_setup_smb1 :do_session_setup_andx_smb1

        def do_logoff_andx_smb1(request, session)
          # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/00fc0299-496c-4330-9089-67358994f272
          @session_table.delete(request.smb_header.uid)
          session.logoff!

          response = SMB1::Packet::LogoffResponse.new
          response
        end

        def do_session_setup_smb2(request, session)
          session_id = request.smb2_header.session_id
          if session_id == 0
            session_id = rand(1..0xfffffffe)
            session = @session_table[session_id] = Session.new(session_id)
          else
            session = @session_table[session_id]
            if session.nil?
              response = SMB2::Packet::ErrorPacket.new
              response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_USER_SESSION_DELETED
              return response
            end
          end

          gss_result = process_gss(request.buffer)
          return if gss_result.nil?

          response = SMB2::Packet::SessionSetupResponse.new
          response.smb2_header.nt_status = gss_result.nt_status.value
          response.smb2_header.credits = 1
          response.smb2_header.message_id = request.smb2_header.message_id
          response.smb2_header.session_id = session_id
          response.buffer = gss_result.buffer

          update_preauth_hash(request) if @dialect == '0x0311'
          if gss_result.nt_status == WindowsError::NTStatus::STATUS_SUCCESS
            session.state = :valid
            session.user_id = gss_result.identity
            session.is_guest = !!gss_result.is_guest
            session.key = @gss_authenticator.session_key
            session.signing_required = request.security_mode.signing_required == 1 || (!session.is_guest && !session.is_anonymous)

            response.smb2_header.credits = 32
            @cipher_id = 0 if session.is_anonymous || session.is_guest # disable encryption for anonymous users and guest users which have a null session key
            response.session_flags.encrypt_data = 1 unless @cipher_id == 0
            response.session_flags.guest = session.is_guest
          elsif gss_result.nt_status == WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED && @dialect == '0x0311'
            update_preauth_hash(response)
          end

          response
        end

        def do_logoff_smb2(request, session)
          # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a6fbc502-75a5-42ef-a88c-c67b44817850
          @session_table.delete(session.id)
          session.logoff!

          response = SMB2::Packet::LogoffResponse.new
          response
        end
      end
    end
  end
end

