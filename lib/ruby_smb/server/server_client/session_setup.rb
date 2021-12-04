module RubySMB
  class Server
    class ServerClient
      module SessionSetup
        # The object representing a single anonymous, guest or authenticated session.
        # @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea10b7ae-b053-4e4c-ab31-a48f7d0a79af
        class Session
          # @param [Integer] id This session's unique identifier.
          # @param [String] key This session's key.
          # @param [Symbol] state The state that this session is in.
          # @param user_id The identity of the user associated with this session.
          def initialize(id, key: nil, state: :in_progress, user_id: nil)
            @id = id
            @key = key
            @user_id = user_id
            @state = state
            @signing_required = false
            # tree id => provider processor instance
            @tree_connect_table = {}
            @creation_time = Time.now
          end

          # Whether or not this session is anonymous.
          # @return [Boolean]
          def is_anonymous
            @user_id == Gss::Provider::IDENTITY_ANONYMOUS
          end

          # This session's unique identifier.
          # @!attribute [rw] id
          #   @return [Integer]
          attr_accessor :id

          # This session's key.
          # @!attribute [rw] key
          #   @return [String]
          attr_accessor :key

          # The identity of the authenticated user.
          # @!attribute [rw] user_id
          attr_accessor :user_id

          # The state that the session is in, (:expired, :in_progress, :valid, etc.).
          # @!attribute [rw] state
          #   @return [Symbol]
          attr_accessor :state

          # Whether or not this session requires messages to be signed.
          # @!attribute [rw] signing_required
          #   @return [Boolean]
          attr_accessor :signing_required

          # The table of tree/share connections in use by this session.
          # @!attribute [rw] tree_connect_table
          #   @return [Hash]
          attr_accessor :tree_connect_table

          # The time at which this session was created.
          # @!attribute [r] creation_time
          #   @return [Time]
          attr_reader   :creation_time
        end

        def do_session_setup_smb1(request)
          gss_result = process_gss(request.data_block.security_blob)
          return if gss_result.nil?

          session_id = request.smb_header.uid
          if session_id == 0
            session_id = rand(0x10000)
            session = @session_table[session_id] = Session.new(session_id)
          else
            session = @session_table[session_id]
          end

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

        def do_session_setup_smb2(request)
          gss_result = process_gss(request.buffer)
          return if gss_result.nil?

          session_id = request.smb2_header.session_id
          if session_id == 0
            session_id = rand(1..0xfffffffe)
            session = @session_table[session_id] = Session.new(session_id)
          else
            session = @session_table[session_id]
            if session.nil?
              response = SMB2::Packet::ErrorPacket.new
              response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_USER_SESSION_DELETED
              response.smb2_header.message_id = request.smb2_header.message_id
              return response
            end
          end

          response = SMB2::Packet::SessionSetupResponse.new
          response.smb2_header.nt_status = gss_result.nt_status.value
          response.smb2_header.credits = 1
          response.smb2_header.message_id = request.smb2_header.message_id
          response.smb2_header.session_id = session_id
          response.buffer = gss_result.buffer

          update_preauth_hash(request) if @dialect == '0x0311'
          if gss_result.nt_status == WindowsError::NTStatus::STATUS_SUCCESS
            response.smb2_header.credits = 32
            session.state = :valid
            session.user_id = gss_result.identity
            session.key = @gss_authenticator.session_key
            session.signing_required = request.security_mode.signing_required == 1
          elsif gss_result.nt_status == WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED && @dialect == '0x0311'
            update_preauth_hash(response)
          end

          response
        end

        def do_logoff_smb2(request, session)
          @session_table.delete(session.id)

          response = SMB2::Packet::LogoffResponse.new
          response
        end
      end
    end
  end
end

