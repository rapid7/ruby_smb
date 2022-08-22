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
    require 'ruby_smb/dcerpc/request'
    require 'ruby_smb/dcerpc/response'
    require 'ruby_smb/dcerpc/rpc_auth3'
    require 'ruby_smb/dcerpc/bind'
    require 'ruby_smb/dcerpc/bind_ack'
    require 'ruby_smb/dcerpc/print_system'
    require 'ruby_smb/dcerpc/encrypting_file_system'

    # Bind to the remote server interface endpoint.
    #
    # @param options [Hash] the options to pass to the Bind request packet. At least, :endpoint must but provided with an existing Dcerpc class
    # @return [BindAck] the BindAck response packet
    # @raise [Error::InvalidPacket] if an invalid packet is received
    # @raise [Error::BindError] if the response is not a BindAck packet or if the Bind result code is not ACCEPTANCE
    def bind(options={})
      bind_req = Bind.new(options)
      if options[:auth_level] && options[:auth_level] != RPC_C_AUTHN_LEVEL_NONE
        case options[:auth_type]
        when RPC_C_AUTHN_WINNT, RPC_C_AUTHN_DEFAULT
          @ntlm_client = @tree.client.ntlm_client
          @ctx_id            = 0
          @call_id           = 1
          @auth_ctx_id_base  = rand(0xFFFFFFFF)
          raise ArgumentError, "NTLM Client not initialized. Username and password must be provided" unless @ntlm_client
          type1_message = @ntlm_client.init_context
          auth = type1_message.serialize
        when RPC_C_AUTHN_GSS_KERBEROS, RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_GSS_NEGOTIATE
        when RPC_C_AUTHN_GSS_KERBEROS, RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_GSS_SCHANNEL
          # TODO
          raise NotImplementedError
        else
          raise ArgumentError, "Unsupported Auth Type: #{options[:auth_type]}"
        end
        add_auth_verifier(bind_req, auth, options[:auth_type], options[:auth_level])
      end
      send_packet(bind_req)
      @size = 1024
      dcerpc_raw_response = read()
      begin
        dcerpc_response = BindAck.read(dcerpc_raw_response)
      rescue IOError
        raise Error::InvalidPacket, "Error reading the DCERPC response"
      end
      unless dcerpc_response.pdu_header.ptype == PTypes::BIND_ACK
        raise Error::BindError, "Not a BindAck packet"
      end

      res_list = dcerpc_response.p_result_list
      if res_list.n_results == 0 ||
         res_list.p_results[0].result != BindAck::ACCEPTANCE
        raise Error::BindError,
          "Bind Failed (Result: #{res_list.p_results[0].result}, Reason: #{res_list.p_results[0].reason})"
      end
      @tree.client.max_buffer_size = dcerpc_response.max_xmit_frag

      if options[:auth_level] && options[:auth_level] != RPC_C_AUTHN_LEVEL_NONE
        # The number of legs needed to build the security context is defined
        # by the security provider
        # (see [2.2.1.1.7 Security Providers](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/d4097450-c62f-484b-872f-ddf59a7a0d36))
        case options[:auth_type]
        when RPC_C_AUTHN_WINNT
          send_auth3(dcerpc_response, options[:auth_type], options[:auth_level])
        when RPC_C_AUTHN_GSS_KERBEROS, RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_GSS_NEGOTIATE
          # TODO
          raise NotImplementedError
        end
      end

      dcerpc_response
    end

    # Send a packet to the remote host
    #
    # @param packet [BinData::Record] the packet to send
    # @raise [Error::CommunicationError] if socket-related error occurs
    def send_packet(packet)
      write(data: packet.to_binary_s)
      nil
    end

    # Add the authentication verifier to the packet. This includes a sec
    # trailer and the actual authentication data.
    #
    # @param req [BinData::Record] the request to be updated
    # @param auth [String] the authentication data
    # @param auth_type [Integer] the authentication type
    # @param auth_level [Integer] the authentication level
    def add_auth_verifier(req, auth, auth_type, auth_level)
      req.sec_trailer = {
        auth_type: auth_type,
        auth_level: auth_level,
        auth_context_id: @ctx_id + @auth_ctx_id_base
      }
      req.auth_value = auth
      req.pdu_header.auth_length = auth.length

      nil
    end

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
    #
    # @param response [BindAck] the BindAck response packet
    # @param auth_type [Integer] the authentication type
    # @param auth_level [Integer] the authentication level
    # @raise [ArgumentError] if `:auth_type` is unknown
    # @raise [NotImplementedError] if `:auth_type` is not implemented (yet)
    def send_auth3(response, auth_type, auth_level)
      case auth_type
      when RPC_C_AUTHN_NONE
      when RPC_C_AUTHN_WINNT, RPC_C_AUTHN_DEFAULT
        auth3 = process_ntlm_type2(response.auth_value)
      when RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_GSS_SCHANNEL, RPC_C_AUTHN_GSS_KERBEROS
        # TODO
        raise NotImplementedError
      else
        raise ArgumentError, "Unsupported Auth Type: #{auth_type}"
      end

      rpc_auth3 = RpcAuth3.new
      add_auth_verifier(rpc_auth3, auth3, auth_type, auth_level)
      rpc_auth3.pdu_header.call_id = @call_id # todo: figure this out for named pipes

      # The server should not respond
      send_packet(rpc_auth3)
      @call_id += 1

      nil
    end
  end
end
