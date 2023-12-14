module RubySMB
  module Dcerpc
    MAX_XMIT_FRAG = 4280
    MAX_RECV_FRAG = 4280

    # Auth Levels
    #[2.2.1.1.8 Authentication Levels](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/425a7c53-c33a-4868-8e5b-2a850d40dc73)
    RPC_C_AUTHN_LEVEL_DEFAULT       = 0
    RPC_C_AUTHN_LEVEL_NONE          = 1
    RPC_C_AUTHN_LEVEL_CONNECT       = 2
    RPC_C_AUTHN_LEVEL_CALL          = 3
    RPC_C_AUTHN_LEVEL_PKT           = 4
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY   = 6

    ## Auth Types
    # [2.2.1.1.7 Security Providers](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/d4097450-c62f-484b-872f-ddf59a7a0d36)
    RPC_C_AUTHN_NONE          = 0x00
    RPC_C_AUTHN_GSS_NEGOTIATE = 0x09
    RPC_C_AUTHN_WINNT         = 0x0A
    RPC_C_AUTHN_GSS_SCHANNEL  = 0x0E
    RPC_C_AUTHN_GSS_KERBEROS  = 0x10
    RPC_C_AUTHN_NETLOGON      = 0x44
    RPC_C_AUTHN_DEFAULT       = 0xFF

    #[Authorisation Services](https://pubs.opengroup.org/onlinepubs/9629399/chap13.htm#tagcjh_18_01_02_03)
    DCE_C_AUTHZ_NAME = 1
    DCE_C_AUTHZ_DCE  = 2

    require 'windows_error/win32'
    require 'ruby_smb/dcerpc/error'
    require 'ruby_smb/dcerpc/fault'
    require 'ruby_smb/dcerpc/uuid'
    require 'ruby_smb/dcerpc/ndr'
    require 'ruby_smb/dcerpc/ptypes'
    require 'ruby_smb/dcerpc/p_syntax_id_t'
    require 'ruby_smb/dcerpc/rrp_rpc_unicode_string'
    require 'ruby_smb/dcerpc/rpc_security_attributes'
    require 'ruby_smb/dcerpc/pdu_header'
    require 'ruby_smb/dcerpc/srvsvc'
    require 'ruby_smb/dcerpc/svcctl'
    require 'ruby_smb/dcerpc/winreg'
    require 'ruby_smb/dcerpc/netlogon'
    require 'ruby_smb/dcerpc/samr'
    require 'ruby_smb/dcerpc/wkssvc'
    require 'ruby_smb/dcerpc/epm'
    require 'ruby_smb/dcerpc/drsr'
    require 'ruby_smb/dcerpc/sec_trailer'
    require 'ruby_smb/dcerpc/dfsnm'
    require 'ruby_smb/dcerpc/icpr'
    require 'ruby_smb/dcerpc/encrypting_file_system'
    require 'ruby_smb/dcerpc/request'
    require 'ruby_smb/dcerpc/response'
    require 'ruby_smb/dcerpc/rpc_auth3'
    require 'ruby_smb/dcerpc/port_any_t'
    require 'ruby_smb/dcerpc/p_cont_list_t'
    require 'ruby_smb/dcerpc/p_result_t'
    require 'ruby_smb/dcerpc/p_result_list_t'
    require 'ruby_smb/dcerpc/alter_context'
    require 'ruby_smb/dcerpc/bind'
    require 'ruby_smb/dcerpc/bind_ack'
    require 'ruby_smb/dcerpc/alter_context_resp'
    require 'ruby_smb/dcerpc/print_system'

    # Initialize the auth provider using NTLM. This function should be overriden for other providers (e.g. Kerberos, etc.)
    # @raise ArgumentError If @ntlm_client isn't initialized with a username and password.
    # @return Serialized message for initializing the auth provider (NTLM, unless this class is extended/overridden)
    def auth_provider_init
      raise ArgumentError, "NTLM Client not initialized. Username and password must be provided" unless @ntlm_client
      type1_message = @ntlm_client.init_context

      type1_message.serialize
    end

    # Encrypt the value in dcerpc_req.stub, and add a valid signature to the request.
    # This function modifies the request object in-place, and does not return anything.
    # This function should be overriden for other providers (e.g. Kerberos, etc.)
    # @param dcerpc_req [Request] The Request object to be encrypted and signed in-place
    def auth_provider_encrypt_and_sign(dcerpc_req)
      auth_type = dcerpc_req.sec_trailer.auth_type
      auth_level = dcerpc_req.sec_trailer.auth_level
      unless [RPC_C_AUTHN_WINNT, RPC_C_AUTHN_DEFAULT].include?(auth_type)
        raise ArgumentError, "Unsupported Auth Type: #{auth_type}"
      end
      plaintext = dcerpc_req.stub.to_binary_s
      pad_length = get_auth_padding_length(plaintext.length)
      dcerpc_req.auth_pad = "\x00" * pad_length
      data_to_sign = plain_stub_with_padding = dcerpc_req.stub.to_binary_s + dcerpc_req.auth_pad.to_binary_s
      dcerpc_req.sec_trailer.auth_pad_length = pad_length
      if @ntlm_client.flags & NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY] != 0
        data_to_sign = dcerpc_req.to_binary_s[0..-(dcerpc_req.pdu_header.auth_length + 1)]
      end

      if auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        encrypted = @ntlm_client.session.seal_message(plain_stub_with_padding)
        set_encrypted_packet(dcerpc_req, encrypted, pad_length)
      end
      signature = @ntlm_client.session.sign_message(data_to_sign)

      set_signature_on_packet(dcerpc_req, signature)
    end

    # Get the response's full stub value (which will include the auth-pad)
    # @param dcerpc_response [Response] The Response object to extract from
    # @return [String] The full stub, including auth_pad
    def get_response_full_stub(dcerpc_response)
      dcerpc_response.stub.to_binary_s + dcerpc_response.auth_pad.to_binary_s
    end

    # Decrypt the value in dcerpc_req.stub, and validate its signature.
    # This function modifies the request object in-place, and returns whether the signature was valid.
    # This function should be overriden for other providers (e.g. Kerberos, etc.)
    # @param dcerpc_response [Response] The Response packet to decrypt and verify in-place
    # @raise ArgumentError If the auth type is not NTLM
    # @return [Boolean] Is the packet's signature valid?
    def auth_provider_decrypt_and_verify(dcerpc_response)
      auth_type = dcerpc_response.sec_trailer.auth_type
      auth_level = dcerpc_response.sec_trailer.auth_level
      unless [RPC_C_AUTHN_WINNT, RPC_C_AUTHN_DEFAULT].include?(auth_type)
        raise ArgumentError, "Unsupported Auth Type: #{auth_type}"
      end
      signature = dcerpc_response.auth_value
      if auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        encrypted_stub = get_response_full_stub(dcerpc_response)
        plaintext = @ntlm_client.session.unseal_message(encrypted_stub)
        set_decrypted_packet(dcerpc_response, plaintext)
      end
      data_to_check = dcerpc_response.stub.to_binary_s
      if @ntlm_client.flags & NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY] != 0
        data_to_check = dcerpc_response.to_binary_s[0..-(dcerpc_response.pdu_header.auth_length + 1)]
      end

      @ntlm_client.session.verify_signature(signature, data_to_check)
    end

    # Completes local initialisation of @ntlm_client using the server's response
    #
    # @param type2_message [String] NTLM type 2 message sent from server
    # @return [String] Type 3 message to be sent to the server to complete the NTLM handshake
    def process_ntlm_type2(type2_message)
      ntlmssp_offset = type2_message.index('NTLMSSP')
      type2_blob = type2_message.slice(ntlmssp_offset..-1)
      type2_b64_message = [type2_blob].pack('m')
      type3_message = @ntlm_client.init_context(type2_b64_message)
      auth3 = type3_message.serialize

      @session_key = @ntlm_client.session_key
      auth3
    end

    # Send a rpc_auth3 PDU that ends the authentication handshake.
    # This function should be overriden for other providers (e.g. Kerberos, etc.)
    #
    # @param response [BindAck] the BindAck response packet
    # @param options [Hash] Unused by the NTLM auth provider
    def auth_provider_complete_handshake(response, options)
      auth3 = process_ntlm_type2(response.auth_value)

      rpc_auth3 = RpcAuth3.new
      add_auth_verifier(rpc_auth3, auth3)
      rpc_auth3.pdu_header.call_id = @call_id

      # The server should not respond
      send_packet(rpc_auth3)
      @call_id += 1

      nil
    end

    def force_set_auth_params(auth_type, auth_level)
      @auth_type = auth_type
      @auth_level = auth_level
    end


    # Bind to the remote server interface endpoint. It takes care of adding
    # the necessary authentication verifier if `:auth_level` is set to
    # anything different than RPC_C_AUTHN_LEVEL_NONE
    #
    # @param [Hash] options
    # @option options [Module] :endpoint the endpoint to bind to. This must be a Dcerpc
    #   class with UUID, VER_MAJOR and VER_MINOR constants defined.
    # @option options [Integer] :auth_level the authentication level
    # @option options [Integer] :auth_type the authentication type
    # @return [BindAck] the BindAck response packet
    # @raise [Error::InvalidPacket] if an invalid packet is received
    # @raise [Error::BindError] if the response is not a BindAck packet or if the Bind result code is not ACCEPTANCE
    # @raise [ArgumentError] if `:auth_type` is unknown
    # @raise [NotImplementedError] if `:auth_type` is not implemented (yet)
    def bind(options={})
      @call_id ||= 1
      bind_req = Bind.new(options)
      bind_req.pdu_header.call_id = @call_id
      auth_type = options.fetch(:auth_type) { RPC_C_AUTHN_WINNT }
      auth_level = options.fetch(:auth_level) { RPC_C_AUTHN_LEVEL_NONE }

      force_set_auth_params(auth_type, auth_level)

      if @auth_level != RPC_C_AUTHN_LEVEL_NONE
        @ctx_id            = 0
        @auth_ctx_id_base  = rand(0xFFFFFFFF)
        auth = auth_provider_init
        add_auth_verifier(bind_req, auth)
      end

      send_packet(bind_req)
      begin
        dcerpc_response = recv_struct(BindAck)
      rescue Error::InvalidPacket
        raise Error::BindError # raise the more context-specific BindError
      end
      # TODO: see if BindNack response should be handled too

      res_list = dcerpc_response.p_result_list
      if res_list.n_results == 0 ||
         res_list.p_results[0].result != BindAck::ACCEPTANCE
        raise Error::BindError,
          "Bind Failed (Result: #{res_list.p_results[0].result}, Reason: #{res_list.p_results[0].reason})"
      end
      self.max_buffer_size = dcerpc_response.max_xmit_frag
      @call_id = dcerpc_response.pdu_header.call_id

      if auth_level != RPC_C_AUTHN_LEVEL_NONE
        # The number of legs needed to build the security context is defined
        # by the security provider
        # (see [2.2.1.1.7 Security Providers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/d4097450-c62f-484b-872f-ddf59a7a0d36))
        auth_provider_complete_handshake(dcerpc_response, options)
      end

      dcerpc_response
    end

    def max_buffer_size=(value)
      @tree.client.max_buffer_size = value
    end

    # Receive a packet from the remote host and parse it according to `struct`
    #
    # @param struct [Class] the structure class to parse the response with
    def recv_struct(struct)
      raw_response = read
      begin
        response = struct.read(raw_response)
      rescue IOError
        raise Error::InvalidPacket, "Error reading the #{struct} response"
      end
      unless response.pdu_header.ptype == struct::PTYPE
        raise Error::InvalidPacket, "Not a #{struct} packet"
      end

      response
    end

    # Send a packet to the remote host
    #
    # @param packet [BinData::Record] the packet to send
    # @raise [Error::CommunicationError] if socket-related error occurs
    def send_packet(packet)
      write(data: packet.to_binary_s)
      nil
    end

    def get_auth_padding_length(plaintext_len)
      (16 - (plaintext_len % 16)) % 16
    end

    # Add the authentication verifier to a Request packet. This includes a
    # sec trailer and the signature of the packet. This also encrypts the
    # Request stub if privacy is required (`:auth_level` option is
    # RPC_C_AUTHN_LEVEL_PKT_PRIVACY).
    #
    # @param dcerpc_req [Request] the Request packet to be updated
    # @param opts [Hash] the authentication options: `:auth_type` and `:auth_level`
    # @raise [NotImplementedError] if `:auth_type` is not implemented (yet)
    # @raise [ArgumentError] if `:auth_type` is unknown
    def set_integrity_privacy(dcerpc_req, auth_level:, auth_type:)
      unless [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY].include?(auth_level)
        raise ArgumentError, "Unsupported Auth Type: #{auth_type}"
      end

      dcerpc_req.sec_trailer = {
        auth_type: auth_type,
        auth_level: auth_level,
        auth_context_id: @ctx_id + @auth_ctx_id_base
      }
      dcerpc_req.auth_value = ' ' * 16
      dcerpc_req.pdu_header.auth_length = 16

      auth_provider_encrypt_and_sign(dcerpc_req)
    end

    def set_signature_on_packet(dcerpc_req, signature)
      dcerpc_req.auth_value = signature
      dcerpc_req.pdu_header.auth_length = signature.size
    end

    def set_encrypted_packet(dcerpc_req, encrypted_stub, pad_length)
      unless encrypted_stub.empty?
        dcerpc_req.enable_encrypted_stub
        dcerpc_req.stub = encrypted_stub[0..-(pad_length+1)]
        if pad_length != 0
          dcerpc_req.auth_pad = encrypted_stub[-(pad_length)..-1]
        end
      end
    end

    def set_decrypted_packet(dcerpc_response, decrypted_stub)
      unless decrypted_stub.empty?
        pad_length = dcerpc_response.sec_trailer.auth_pad_length.to_i
        dcerpc_response.stub = decrypted_stub[0..-(pad_length + 1)]
        dcerpc_response.auth_pad = decrypted_stub[-(pad_length + 1)..-1]
      end
    end

    # Process the security context received in a response. It decrypts the
    # encrypted stub if `:auth_level` is set to anything different than
    # RPC_C_AUTHN_LEVEL_PKT_PRIVACY. It also checks the packet signature and
    # raises an InvalidPacket error if it fails. Note that the exception is
    # disabled by default and can be enabled with the
    # `:raise_signature_error` option
    #
    # @param dcerpc_response [Response] the Response packet
    #   containing the security context to process
    # @param opts [Hash] the authentication options: `:auth_type` and
    #   `:auth_level`. To enable errors when signature check fails, set the
    #   `:raise_signature_error` option to true
    # @raise [NotImplementedError] if `:auth_type` is not implemented (yet)
    # @raise [Error::CommunicationError] if socket-related error occurs
    def handle_integrity_privacy(dcerpc_response, auth_level:, auth_type:, raise_signature_error: false)
      unless [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY].include?(auth_level)
        raise ArgumentError, "Unsupported Auth Type: #{auth_type}"
      end
      signature_valid = auth_provider_decrypt_and_verify(dcerpc_response)

      unless signature_valid
        if raise_signature_error
          raise Error::InvalidPacket.new(
            "Wrong packet signature received (set `raise_signature_error` to false to ignore)"
          )
        end
      end

      @call_id += 1

      nil
    end

    # Add the authentication verifier to the packet. This includes a sec
    # trailer and the actual authentication data.
    #
    # @param req [BinData::Record] the request to be updated
    # @param auth [String] the authentication data
    def add_auth_verifier(req, auth)
      req.sec_trailer = {
        auth_type: @auth_type,
        auth_level: @auth_level,
        auth_context_id: @ctx_id + @auth_ctx_id_base
      }
      req.auth_value = auth
      req.pdu_header.auth_length = auth.length

      nil
    end
  end
end
