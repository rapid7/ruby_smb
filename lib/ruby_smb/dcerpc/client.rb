module RubySMB
  module Dcerpc

    # Represents DCERPC SMB client capable of talking to an RPC endpoint in stand-alone.
    class Client
      require 'bindata'
      require 'windows_error'
      require 'net/ntlm'
      require 'ruby_smb/dcerpc'
      require 'ruby_smb/gss'

      include Epm

      # The default maximum size of a RPC message that the Client accepts (in bytes)
      MAX_BUFFER_SIZE = 64512
      # The read timeout when sending and receiving packets.
      READ_TIMEOUT = 30

      # The domain you're trying to authenticate to
      # @!attribute [rw] domain
      #   @return [String]
      attr_accessor :domain

      # The local workstation to pretend to be
      # @!attribute [rw] local_workstation
      #   @return [String]
      attr_accessor :local_workstation

      # The NTLM client used for authentication
      # @!attribute [rw] ntlm_client
      #   @return [String]
      attr_accessor :ntlm_client

      # The username to authenticate with
      # @!attribute [rw] username
      #   @return [String]
      attr_accessor :username

      # The password to authenticate with
      # @!attribute [rw] password
      #   @return [String]
      attr_accessor :password

      # The Netbios Name of the Peer/Server.
      # @!attribute [rw] default_name
      #   @return [String]
      attr_accessor :default_name

      # The Netbios Domain of the Peer/Server.
      # @!attribute [rw] default_domain
      #   @return [String]
      attr_accessor :default_domain

      # The Fully Qualified Domain Name (FQDN) of the computer.
      # @!attribute [rw] dns_host_name
      #   @return [String]
      attr_accessor :dns_host_name

      # The Fully Qualified Domain Name (FQDN) of the domain.
      # @!attribute [rw] dns_domain_name
      #   @return [String]
      attr_accessor :dns_domain_name

      # The Fully Qualified Domain Name (FQDN) of the forest.
      # @!attribute [rw] dns_tree_name
      #   @return [String]
      attr_accessor :dns_tree_name

      # The OS version number (<major>.<minor>.<build>) of the Peer/Server.
      # @!attribute [rw] os_version
      #   @return [String]
      attr_accessor :os_version

      # The maximum size SMB message that the Client accepts (in bytes)
      # The default value is equal to {MAX_BUFFER_SIZE}.
      # @!attribute [rw] max_buffer_size
      #   @return [Integer]
      attr_accessor :max_buffer_size

      # The TCP socket to connect to the remote host
      # @!attribute [rw] tcp_socket
      #   @return [TcpSocket]
      attr_accessor :tcp_socket


      # @param host [String] The remote host
      # @param endpoint [Module] A module endpoint that defines UUID, VER_MAJOR and
      #   VER_MINOR constants (e.g. Drsr)
      # @param tcp_socket [TcpSocket] The socket to use. If not provided, a new
      #   socket will be created when calling #connect
      # @param read_timeout [Integer] The read timeout value to use
      # @param username [String] The username to authenticate with, if needed
      # @param password [String] The password to authenticate with, if needed.
      #   Note that a NTLM hash can be used instead of a password.
      # @param domain [String] The domain to authenticate to, if needed
      # @param local_workstation [String] The workstation name to authenticate to, if needed
      # @param ntlm_flags [Integer] The flags to pass to the Net:NTLM client
      def initialize(host,
                     endpoint,
                     tcp_socket: nil,
                     read_timeout: READ_TIMEOUT,
                     username: '',
                     password: '',
                     domain: '.',
                     local_workstation: 'WORKSTATION',
                     ntlm_flags: NTLM::DEFAULT_CLIENT_FLAGS)

        @endpoint = endpoint
        extend @endpoint

        @host              = host
        @tcp_socket        = tcp_socket
        @read_timeout      = read_timeout
        @domain            = domain
        @local_workstation = local_workstation
        @username          = username.encode('utf-8')
        @password          = password.encode('utf-8')
        @max_buffer_size   = MAX_BUFFER_SIZE
        @call_id           = 1
        @ctx_id            = 0
        @auth_ctx_id_base  = rand(0xFFFFFFFF)

        unless username.empty? && password.empty?
          @ntlm_client = Net::NTLM::Client.new(
            @username,
            @password,
            workstation: @local_workstation,
            domain: @domain,
            flags: ntlm_flags
          )
        end
      end

      # Connect to the RPC endpoint. If a TCP socket was not provided, it takes
      # care of asking the Enpoint Mapper Interface the port used by the given
      # endpoint provided in #initialize and connect a TCP socket
      #
      # @param port [Integer] An optional port number to connect to. If
      #   provided, it will not ask the Enpoint Mapper Interface for a port
      #   number.
      # @return [TcpSocket] The connected TCP socket
      def connect(port: nil)
        return if @tcp_socket
        unless port
          @tcp_socket = TCPSocket.new(@host, 135)
          bind(endpoint: Epm)
          host_port = get_host_port_from_ept_mapper(
            uuid: @endpoint::UUID,
            maj_ver: @endpoint::VER_MAJOR,
            min_ver: @endpoint::VER_MINOR
          )
          port = host_port[:port]
          @tcp_socket.close
          @tcp_socket = nil
        end
        @tcp_socket = TCPSocket.new(@host, port)
      end

      # Close the TCP Socket
      def close
        @tcp_socket.close if @tcp_socket && !@tcp_socket.closed?
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
        challenge_message = @ntlm_client.session.challenge_message
        store_target_info(challenge_message.target_info) if challenge_message.has_flag?(:TARGET_INFO)
        @os_version = extract_os_version(challenge_message.os_version.to_s) unless challenge_message.os_version.empty?
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
        when RPC_C_AUTHN_WINNT
          auth3 = process_ntlm_type2(response.auth_value)
        when RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_GSS_NEGOTIATE
          # TODO
          raise NotImplementedError
        else
          raise ArgumentError, "Unsupported Auth Type: #{auth_type}"
        end

        rpc_auth3 = RpcAuth3.new
        add_auth_verifier(rpc_auth3, auth3, auth_type, auth_level)
        rpc_auth3.pdu_header.call_id = @call_id

        # The server should not respond
        send_packet(rpc_auth3)
        @call_id += 1

        nil
      end

      # Bind to the remote server interface endpoint. It takes care of adding
      # the necessary authentication verifier if `:auth_level` is set to
      # anything different than RPC_C_AUTHN_LEVEL_NONE
      #
      # @param endpoint [Module] the endpoint to bind to. This must be a Dcerpc
      #   class with UUID, VER_MAJOR and VER_MINOR constants defined.
      # @param auth_level [Integer] the authentication level
      # @param auth_type [Integer] the authentication type
      # @return [BindAck] the BindAck response packet
      # @raise [Error::InvalidPacket] if an invalid packet is received
      # @raise [Error::BindError] if the response is not a BindAck packet or if the Bind result code is not ACCEPTANCE
      # @raise [ArgumentError] if `:auth_type` is unknown
      # @raise [NotImplementedError] if `:auth_type` is not implemented (yet)
      def bind(endpoint: @endpoint, auth_level: RPC_C_AUTHN_LEVEL_NONE, auth_type: nil)
        bind_req = Bind.new(endpoint: endpoint)
        bind_req.pdu_header.call_id = @call_id
        # TODO: evasion: generate random UUIDs for bogus binds

        if auth_level && auth_level != RPC_C_AUTHN_LEVEL_NONE
          case auth_type
          when RPC_C_AUTHN_WINNT
            raise ArgumentError, "NTLM Client not initialized. Username and password must be provided" unless @ntlm_client
            type1_message = @ntlm_client.init_context
            auth = type1_message.serialize
          when RPC_C_AUTHN_GSS_KERBEROS, RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_GSS_NEGOTIATE
            # TODO
            raise NotImplementedError
          else
            raise ArgumentError, "Unsupported Auth Type: #{auth_type}"
          end
          add_auth_verifier(bind_req, auth, auth_type, auth_level)
        end

        send_packet(bind_req)
        bindack_response = recv_packet(BindAck)
        # TODO: see if BindNack response should be handled too

        res_list = bindack_response.p_result_list
        if res_list.n_results == 0 ||
           res_list.p_results[0].result != BindAck::ACCEPTANCE
          raise Error::BindError,
            "Bind Failed (Result: #{res_list.p_results[0].result}, Reason: #{res_list.p_results[0].reason})"
        end

        @max_buffer_size = bindack_response.max_xmit_frag
        @call_id = bindack_response.pdu_header.call_id

        if auth_level && auth_level != RPC_C_AUTHN_LEVEL_NONE
           # The number of legs needed to build the security context is defined
           # by the security provider
           # (see [2.2.1.1.7 Security Providers](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/d4097450-c62f-484b-872f-ddf59a7a0d36))
          case auth_type
          when RPC_C_AUTHN_WINNT
            send_auth3(bindack_response, auth_type, auth_level)
          when RPC_C_AUTHN_GSS_KERBEROS, RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_GSS_NEGOTIATE
            # TODO
            raise NotImplementedError
          end
        end

        nil
      end

      # Extract and store useful information about the peer/server from the
      # NTLM Type 2 (challenge) TargetInfo fields.
      #
      # @param target_info_str [String] the Target Info string
      def store_target_info(target_info_str)
        target_info = Net::NTLM::TargetInfo.new(target_info_str)
        {
          Net::NTLM::TargetInfo::MSV_AV_NB_COMPUTER_NAME  => :@default_name,
          Net::NTLM::TargetInfo::MSV_AV_NB_DOMAIN_NAME    => :@default_domain,
          Net::NTLM::TargetInfo::MSV_AV_DNS_COMPUTER_NAME => :@dns_host_name,
          Net::NTLM::TargetInfo::MSV_AV_DNS_DOMAIN_NAME   => :@dns_domain_name,
          Net::NTLM::TargetInfo::MSV_AV_DNS_TREE_NAME     => :@dns_tree_name
        }.each do |constant, attribute|
          if target_info.av_pairs[constant]
            value = target_info.av_pairs[constant].dup
            value.force_encoding('UTF-16LE')
            instance_variable_set(attribute, value.encode('UTF-8'))
          end
        end
      end

      # Extract the peer/server version number from the NTLM Type 2 (challenge)
      # Version field.
      #
      # @param version [String] the version number as a binary string
      # @return [String] the formated version number (<major>.<minor>.<build>)
      def extract_os_version(version)
        version.unpack('CCS').join('.')
      end

      # Add the authentication verifier to a Request packet. This includes a
      # sec trailer and the signature of the packet. This also encrypts the
      # Request stub if privacy is required (`:auth_level` option is
      # RPC_C_AUTHN_LEVEL_PKT_PRIVACY).
      #
      # @param dcerpc_req [Request] the Request packet to be updated
      # @param opts [Hash] the authenticaiton options: `:auth_type` and `:auth_level`
      # @raise [NotImplementedError] if `:auth_type` is not implemented (yet)
      # @raise [ArgumentError] if `:auth_type` is unknown
      def set_integrity_privacy(dcerpc_req, auth_level:, auth_type:)
        dcerpc_req.sec_trailer = {
          auth_type: auth_type,
          auth_level: auth_level,
          auth_context_id: @ctx_id + @auth_ctx_id_base
        }
        dcerpc_req.auth_value = ' ' * 16
        dcerpc_req.pdu_header.auth_length = 16

        data_to_sign = plain_stub = dcerpc_req.stub.to_binary_s + dcerpc_req.auth_pad.to_binary_s
        if @ntlm_client.flags & NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY] != 0
          data_to_sign = dcerpc_req.to_binary_s[0..-(dcerpc_req.pdu_header.auth_length + 1)]
        end

        encrypted_stub = ''
        if auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY
          case auth_type
          when RPC_C_AUTHN_WINNT
            encrypted_stub = @ntlm_client.session.seal_message(plain_stub)
          when RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_GSS_NEGOTIATE
            # TODO
            raise NotImplementedError
          else
            raise ArgumentError, "Unsupported Auth Type: #{auth_type}"
          end
        end

        signature = @ntlm_client.session.sign_message(data_to_sign)

        unless encrypted_stub.empty?
          pad_length = dcerpc_req.sec_trailer.auth_pad_length.to_i
          dcerpc_req.enable_encrypted_stub
          dcerpc_req.stub = encrypted_stub[0..-(pad_length + 1)]
          dcerpc_req.auth_pad = encrypted_stub[-(pad_length)..-1]
        end
        dcerpc_req.auth_value = signature
        dcerpc_req.pdu_header.auth_length = signature.size
      end

      # Send a DCERPC request with the provided stub packet.
      #
      # @param stub_packet [BinData::Record] the stub packet to be sent as
      #   part of a Request packet
      # @param opts [Hash] the authenticaiton options: `:auth_type` and `:auth_level`
      # @raise [Error::CommunicationError] if socket-related error occurs
      def dcerpc_request(stub_packet, auth_level: nil, auth_type: nil)
        stub_class = stub_packet.class.name.split('::')
        #opts.merge!(endpoint: stub_class[-2])
        values = {
          opnum: stub_packet.opnum,
          p_cont_id: @ctx_id
        }
        dcerpc_req = Request.new(values, { endpoint: stub_class[-2] })
        dcerpc_req.pdu_header.call_id = @call_id
        dcerpc_req.stub.read(stub_packet.to_binary_s)
        # TODO: handle fragmentation
        # We should fragment PDUs if:
        # 1) Payload exceeds max_xmit_frag (@max_buffer_size) received during BIND response
        # 2) We'e explicitly fragmenting packets with lower values

        if auth_level &&
           [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY].include?(auth_level)
          set_integrity_privacy(dcerpc_req, auth_level: auth_level, auth_type: auth_type)
        end

        send_packet(dcerpc_req)

        dcerpc_res = recv_packet(Response)
        unless dcerpc_res.pdu_header.pfc_flags.first_frag == 1
          raise Error::InvalidPacket, "Not the first fragment"
        end

        if auth_level &&
           [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY].include?(auth_level)
          handle_integrity_privacy(dcerpc_res, auth_level: auth_level, auth_type: auth_type)
        end

        raw_stub = dcerpc_res.stub.to_binary_s
        loop do
          break if dcerpc_res.pdu_header.pfc_flags.last_frag == 1
          dcerpc_res = recv_packet(Response)

          if auth_level &&
             [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY].include?(auth_level)
            handle_integrity_privacy(dcerpc_res, auth_level: auth_level, auth_type: auth_type)
          end

          raw_stub << dcerpc_res.stub.to_binary_s
        end

        raw_stub
      end

      # Send a packet to the remote host
      #
      # @param packet [BinData::Record] the packet to send
      # @raise [Error::CommunicationError] if socket-related error occurs
      def send_packet(packet)
        data = packet.to_binary_s
        bytes_written = 0
        begin
          loop do
            break unless bytes_written < data.size
            retval = @tcp_socket.write(data[bytes_written..-1])
            bytes_written += retval
          end

        rescue IOError, Errno::ECONNABORTED, Errno::ECONNRESET, Errno::EPIPE => e
          raise Error::CommunicationError, "An error occurred writing to the Socket: #{e.message}"
        end
        nil
      end

      # Receive a packet from the remote host
      #
      # @param struct [Class] the structure class to parse the response with
      # @raise [Error::CommunicationError] if socket-related error occurs
      def recv_packet(struct)
        raise Error::CommunicationError, 'Connection has already been closed' if @tcp_socket.closed?
        if IO.select([@tcp_socket], nil, nil, @read_timeout).nil?
          raise Error::CommunicationError, "Read timeout expired when reading from the Socket (timeout=#{@read_timeout})"
        end

        begin
          response = struct.read(@tcp_socket)
        rescue IOError
          raise Error::InvalidPacket, "Error reading the #{struct} response"
        end
        unless response.pdu_header.ptype == struct::PTYPE
          raise Error::InvalidPacket, "Not a #{struct} packet"
        end

        response
      rescue Errno::EINVAL, Errno::ECONNABORTED, Errno::ECONNRESET, Errno::EPIPE => e
        raise Error::CommunicationError, "An error occurred reading from the Socket: #{e.message}"
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
      # @param opts [Hash] the authenticaiton options: `:auth_type` and
      #   `:auth_level`. To enable errors when signature check fails, set the
      #   `:raise_signature_error` option to true
      # @raise [NotImplementedError] if `:auth_type` is not implemented (yet)
      # @raise [Error::CommunicationError] if socket-related error occurs
      def handle_integrity_privacy(dcerpc_response, auth_level:, auth_type:, raise_signature_error: false)
        decrypted_stub = ''
        if auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY
          encrypted_stub = dcerpc_response.stub.to_binary_s + dcerpc_response.auth_pad.to_binary_s
          case auth_type
          when RPC_C_AUTHN_WINNT
            decrypted_stub = @ntlm_client.session.unseal_message(encrypted_stub)
          when RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_GSS_NEGOTIATE
            # TODO
            raise NotImplementedError
          else
            raise ArgumentError, "Unsupported Auth Type: #{auth_type}"
          end
        end

        unless decrypted_stub.empty?
          pad_length = dcerpc_response.sec_trailer.auth_pad_length.to_i
          dcerpc_response.stub = decrypted_stub[0..-(pad_length + 1)]
          dcerpc_response.auth_pad = decrypted_stub[-(pad_length)..-1]
        end

        signature = dcerpc_response.auth_value
        data_to_check = dcerpc_response.stub.to_binary_s
        if @ntlm_client.flags & NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY] != 0
          data_to_check = dcerpc_response.to_binary_s[0..-(dcerpc_response.pdu_header.auth_length + 1)]
        end
        unless @ntlm_client.session.verify_signature(signature, data_to_check)
          if raise_signature_error
            raise Error::InvalidPacket.new(
              "Wrong packet signature received (set `raise_signature_error` to false to ignore)"
            )
          end
        end

        @call_id += 1

        nil
      end

    end
  end
end

