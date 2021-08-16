require 'bindata'
require 'windows_error'
require 'net/ntlm'
require 'ruby_smb/dcerpc'
require 'ruby_smb/gss'

module RubySMB
  module Dcerpc

    # Represents DCERPC SMB client capable of talking to an RPC endpoint in stand-alone.
    class Client
      include RubySMB::Dcerpc::Epm

      # The default maximum size of a RPC message that the Client accepts (in bytes)
      MAX_BUFFER_SIZE = 64512
      # The read timeout when sending and receiving packets.
      READ_TIMEOUT = 30

      def default_flags
        negotiate_version_flag = 0x02000000
        flags = Net::NTLM::Client::DEFAULT_FLAGS |
          Net::NTLM::FLAGS[:TARGET_INFO] |
          negotiate_version_flag ^
          Net::NTLM::FLAGS[:OEM]

        flags
      end

      # @param host [String] The remote host
      # @param endpoint [Module] A module endpoint that defines UUID, VER_MAJOR and
      #   VER_MINOR constants (e.g. RubySMB::Dcerpc::Drsr)
      # @param tcp_socket [TcpSocket] The socket to use. If not provided, a new
      #   socket will be created when calling #connect
      # @param read_timeout [Integer] The read timeout value to use
      # @param username [String] The username to authenticate with, if needed
      # @param password [String] The password to authenticate with, if needed
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
                     ntlm_flags: default_flags)

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
          bind(endpoint: RubySMB::Dcerpc::Epm)
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
        @tcp_socket.close
      end

      # Add the authentication verifier to the Bind packet. This includes a sec
      # trailer and the actual authentication data based on the value of
      # `:auth_level` and `:auth_type` options.
      #
      # @param bind_req [RubySMB::Dcerpc::Bind] the Bind request to be updated
      # @param opts [Hash] the authenticaiton options: `:auth_type` and `:auth_level`
      # @raise [ArgumentError] if `:auth_type` is unknown
      def add_auth_verifier(bind_req, opts = {})
        case opts[:auth_type]
        when RPC_C_AUTHN_WINNT
          raise ArgumentError, "NTLM Client not initialized. Username and password must be provided" unless @ntlm_client
          type1_message = @ntlm_client.init_context
          auth = type1_message.serialize
        when RPC_C_AUTHN_NETLOGON
          # TODO
        when RPC_C_AUTHN_GSS_NEGOTIATE
          # TODO
        else
          raise ArgumentError, "Unsupported Auth Type: #{opts[:auth_type]}"
        end

        bind_req.sec_trailer = {
          auth_type: opts[:auth_type],
          auth_level: opts[:auth_level],
          auth_context_id: @ctx_id + @auth_ctx_id_base
        }
        bind_req.auth_value = auth
        bind_req.pdu_header.auth_length = auth.length

        nil
      end

      # Send a rpc_auth3 PDU that ends the authentication handshake.
      #
      # @param bindack_response [RubySMB::Dcerpc::BindAck] the BindAck response packet
      # @param opts [Hash] the authenticaiton options: `:auth_type` and `:auth_level`
      def send_auth3(bindack_response, opts = {})
        case opts[:auth_type]
        when RPC_C_AUTHN_WINNT
          sec_blob = bindack_response.auth_value
          ntlmssp_offset = sec_blob.index('NTLMSSP')
          type2_blob = sec_blob.slice(ntlmssp_offset..-1)
          type2_b64_message = [type2_blob].pack('m')
          type3_message = @ntlm_client.init_context(type2_b64_message)
          auth3 = type3_message.serialize

          @session_key = @ntlm_client.session_key
          challenge_message = @ntlm_client.session.challenge_message
          store_target_info(challenge_message.target_info) if challenge_message.has_flag?(:TARGET_INFO)
          @os_version = extract_os_version(challenge_message.os_version.to_s) unless challenge_message.os_version.empty?
        when RPC_C_AUTHN_NETLOGON
          # TODO
        when RPC_C_AUTHN_GSS_NEGOTIATE
          # TODO
        end

        rpc_auth3 = RubySMB::Dcerpc::RpcAuth3.new
        rpc_auth3.sec_trailer = {
          auth_type: opts[:auth_type],
          auth_level: opts[:auth_level],
          auth_context_id: @ctx_id + @auth_ctx_id_base
        }
        rpc_auth3.auth_value = auth3
        rpc_auth3.pdu_header.auth_length = auth3.length
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
      # @param ops [Hash] the options to pass to the Bind request packet.
      #   At least, :endpoint must but provided with an existing Dcerpc class
      # @return [RubySMB::Dcerpc::BindAck] the BindAck response packet
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if an invalid packet is received
      # @raise [RubySMB::Dcerpc::Error::BindError] if the response is not a BindAck packet or if the Bind result code is not ACCEPTANCE
      def bind(opts = {})
        bind_req = RubySMB::Dcerpc::Bind.new(opts)
        bind_req.pdu_header.call_id = @call_id
        # TODO: evasion: generate random UUIDs for bogus binds
        if opts[:lmhash].to_s != '' || opts[:nthash].to_s != ''
          # TODO
        end

        if opts[:auth_level] && opts[:auth_level] != RPC_C_AUTHN_LEVEL_NONE
          add_auth_verifier(bind_req, opts)
        end

        send_packet(bind_req)
        bindack_response = recv_packet(RubySMB::Dcerpc::BindAck)

        #begin
        #  # TODO: handle BinNack response too
        #  bindack_response = RubySMB::Dcerpc::BindAck.read(raw_response)
        #rescue IOError
        #  raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the BindAck response"
        #end
        #unless bindack_response.pdu_header.ptype == RubySMB::Dcerpc::PTypes::BIND_ACK
        #  raise RubySMB::Dcerpc::Error::BindError, "Not a BindAck packet"
        #end

        res_list = bindack_response.p_result_list
        if res_list.n_results == 0 ||
           res_list.p_results[0].result != RubySMB::Dcerpc::BindAck::ACCEPTANCE
          raise RubySMB::Dcerpc::Error::BindError,
            "Bind Failed (Result: #{res_list.p_results[0].result}, Reason: #{res_list.p_results[0].reason})"
        end

        @max_buffer_size = bindack_response.max_xmit_frag
        @call_id = bindack_response.pdu_header.call_id

        if opts[:auth_level] && opts[:auth_level] != RPC_C_AUTHN_LEVEL_NONE
          send_auth3(bindack_response, opts)
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
      # @param dcerpc_req [RubySMB::Dcerpc::Request] the Request packet to be updated
      # @param opts [Hash] the authenticaiton options: `:auth_type` and `:auth_level`
      # @raise [ArgumentError] if `:auth_type` is unknown
      def set_integrity_privacy(dcerpc_req, opts)
        dcerpc_req.sec_trailer = {
          auth_type: opts[:auth_type],
          auth_level: opts[:auth_level],
          auth_context_id: @ctx_id + @auth_ctx_id_base
        }
        dcerpc_req.auth_value = ' ' * 16
        dcerpc_req.pdu_header.auth_length = 16

        data_to_sign = plain_stub = dcerpc_req.stub.to_binary_s + dcerpc_req.auth_pad.to_binary_s
        if @ntlm_client.flags & Net::NTLM::FLAGS[:NTLM2_KEY]
          data_to_sign = dcerpc_req.to_binary_s[0..-(dcerpc_req.pdu_header.auth_length + 1)]
        end

        encrypted_stub = ''
        if opts[:auth_level] == RPC_C_AUTHN_LEVEL_PKT_PRIVACY
          case opts[:auth_type]
          when RPC_C_AUTHN_WINNT
            encrypted_stub = @ntlm_client.session.seal_message(plain_stub)
          when RPC_C_AUTHN_NETLOGON
            # TODO
          when RPC_C_AUTHN_GSS_NEGOTIATE
            # TODO
          else
            raise ArgumentError, "Unsupported Auth Type: #{opts[:auth_type]}"
          end
        end

        signature = @ntlm_client.session.sign_message(data_to_sign)

        pad_length = dcerpc_req.sec_trailer.auth_pad_length.to_i
        dcerpc_req.enable_encrypted_stub
        dcerpc_req.stub = encrypted_stub[0..-(pad_length + 1)]
        dcerpc_req.auth_pad = encrypted_stub[-(pad_length)..-1]
        dcerpc_req.auth_value = signature
        dcerpc_req.pdu_header.auth_length = signature.size
      end

      # Send a DCERPC request with the provided stub packet.
      #
      # @param stub_packet [BinData::Record] the stub packet to be sent as
      #   part of a Request packet
      # @param opts [Hash] the authenticaiton options: `:auth_type` and `:auth_level`
      # @raise [RubySMB::Dcerpc::Error::CommunicationError] if socket-related error occurs
      def dcerpc_request(stub_packet, opts = {})
        stub_class = stub_packet.class.name.split('::')
        opts.merge!(endpoint: stub_class[-2])
        values = {
          opnum: stub_packet.opnum,
          p_cont_id: @ctx_id
        }
        dcerpc_req = RubySMB::Dcerpc::Request.new(values, opts)
        dcerpc_req.pdu_header.call_id = @call_id
        dcerpc_req.stub.read(stub_packet.to_binary_s)
        # TODO: handle fragmentation
        # We should fragment PDUs if:
        # 1) Payload exceeds max_xmit_frag (@max_buffer_size) received during BIND response
        # 2) We'e explicitly fragmenting packets with lower values

        if opts[:auth_level] &&
           [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY].include?(opts[:auth_level])
          set_integrity_privacy(dcerpc_req, opts)
        end

        send_packet(dcerpc_req)

        if @tcp_socket.closed?
          raise RubySMB::Dcerpc::Error::CommunicationError, 'Connection has already been closed'
        end
        if IO.select([@tcp_socket], nil, nil, @read_timeout).nil?
          raise RubySMB::Dcerpc::Error::CommunicationError.new(
            "Read timeout expired when reading from the Socket (timeout=#{@read_timeout})"
          )
        end
        begin
          dcerpc_res = RubySMB::Dcerpc::Response.read(@tcp_socket)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading the DCERPC response'
        end
        unless dcerpc_res.pdu_header.ptype == RubySMB::Dcerpc::PTypes::RESPONSE
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Not a Response packet"
        end
        unless dcerpc_res.pdu_header.pfc_flags.first_frag == 1
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Not the first fragment"
        end

        if opts[:auth_level] &&
           [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY].include?(opts[:auth_level])
          opts[:raise_signature_error] = false
          handle_integrity_privacy(dcerpc_res, opts)
        end

        raw_stub = dcerpc_res.stub.to_binary_s
        loop do
          break if dcerpc_res.pdu_header.pfc_flags.last_frag == 1
          if @tcp_socket.closed?
            raise RubySMB::Dcerpc::Error::CommunicationError, 'Connection has already been closed'
          end
          if IO.select([@tcp_socket], nil, nil, @read_timeout).nil?
            raise RubySMB::Dcerpc::Error::CommunicationError.new(
              "Read timeout expired when reading from the Socket (timeout=#{@read_timeout})"
            )
          end
          begin
            dcerpc_res = RubySMB::Dcerpc::Response.read(@tcp_socket)
          rescue IOError
            raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading the DCERPC response'
          end
          unless dcerpc_res.pdu_header.ptype == RubySMB::Dcerpc::PTypes::RESPONSE
            raise RubySMB::Dcerpc::Error::InvalidPacket, "Not a Response packet"
          end

          if opts[:auth_level] &&
             [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY].include?(opts[:auth_level])
            handle_integrity_privacy(dcerpc_res, opts)
          end

          raw_stub << dcerpc_res.stub.to_binary_s
        end

        raw_stub
      end

      # Send and receive a Request packet
      #
      # @param packet [RubySMB::Dcerpc::Request] the Request packet to send
      # @param opts [Hash] the authenticaiton options: `:auth_type` and `:auth_level`
      def send_recv(packet, opts = {})
        send_packet(packet)
        response = recv_packet(RubySMB::Dcerpc::Response)

        stub_class_name = packet.stub.class.name.split('::')
        stub_class_name[-1].sub!(/Request$/, 'Response')
        stub_class = Object.const_get(res_class_name.join('::'))
        dcerpc_response = dcerpc_response_from_raw_response(response, opts)
      end

      # Send a packet to the remote host
      #
      # @param packet [BinData::Record] the packet to send
      # @raise [RubySMB::Dcerpc::Error::CommunicationError] if socket-related error occurs
      def send_packet(packet)
        data = packet.to_binary_s
        bytes_written = 0
        begin
          loop do
            break unless bytes_written < data.size
            retval = @tcp_socket.write(data[bytes_written..-1])

            if retval == nil
              raise RubySMB::Dcerpc::Error::CommunicationError
            else
              bytes_written += retval
            end
          end

        rescue IOError, Errno::ECONNABORTED, Errno::ECONNRESET => e
          raise RubySMB::Dcerpc::Error::CommunicationError, "An error occurred writing to the Socket: #{e.message}"
        end
        nil
      end

      # Receive a packet from the remote host
      #
      # @param struct [Class] the structure class to parse the response with
      # @raise [RubySMB::Dcerpc::Error::CommunicationError] if socket-related error occurs
      def recv_packet(struct)
        raise RubySMB::Dcerpc::Error::CommunicationError, 'Connection has already been closed' if @tcp_socket.closed?
        if IO.select([@tcp_socket], nil, nil, @read_timeout).nil?
          raise RubySMB::Dcerpc::Error::CommunicationError, "Read timeout expired when reading from the Socket (timeout=#{@read_timeout})"
        end

        begin
          struct.read(@tcp_socket)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the #{struct} response"
        end
      rescue Errno::EINVAL, Errno::ECONNABORTED, Errno::ECONNRESET, TypeError, NoMethodError => e
        raise RubySMB::Error::CommunicationError, "An error occurred reading from the Socket #{e.message}"
      end

      # Process the security context received in a response. It decrypts the
      # encrypted stub if `:auth_level` is set to anything different than
      # RPC_C_AUTHN_LEVEL_PKT_PRIVACY. It also checks the packet signature and
      # raises an InvalidPacket error if it fails. Note that the exception is
      # disabled by default and can be enabled with the
      # `:raise_signature_error` option
      #
      # @param dcerpc_response [RubySMB::Dcerpc::Response] the Response packet
      #   containing the security context to process
      # @param opts [Hash] the authenticaiton options: `:auth_type` and
      #   `:auth_level`. To enable errors when signature check fails, set the
      #   `:raise_signature_error` option to true
      # @raise [RubySMB::Dcerpc::Error::CommunicationError] if socket-related error occurs
      def handle_integrity_privacy(dcerpc_response, opts)
        encrypted_stub = dcerpc_response.stub.to_binary_s + dcerpc_response.auth_pad.to_binary_s
        decrypted_stub = ''
        if opts[:auth_level] == RPC_C_AUTHN_LEVEL_PKT_PRIVACY
          case opts[:auth_type]
          when RPC_C_AUTHN_WINNT
            decrypted_stub = @ntlm_client.session.unseal_message(encrypted_stub)
          when RPC_C_AUTHN_NETLOGON
            # TODO
          when RPC_C_AUTHN_GSS_NEGOTIATE
            # TODO
          else
            raise ArgumentError, "Unsupported Auth Type: #{opts[:auth_type]}"
          end
        end

        pad_length = dcerpc_response.sec_trailer.auth_pad_length.to_i
        dcerpc_response.stub = decrypted_stub[0..-(pad_length + 1)]
        dcerpc_response.auth_pad = decrypted_stub[-(pad_length)..-1]

        signature = dcerpc_response.auth_value
        data_to_check = dcerpc_response.stub.to_binary_s
        if @ntlm_client.flags & Net::NTLM::FLAGS[:NTLM2_KEY]
          data_to_check = dcerpc_response.to_binary_s[0..-(dcerpc_response.pdu_header.auth_length + 1)]
        end
        unless @ntlm_client.session.verify_signature(signature, data_to_check)
          if opts[:raise_signature_error]
            raise RubySMB::Dcerpc::Error::InvalidPacket.new(
              "Wrong packet signature received (checked because opts[:check_signature] is set)"
            )
          end
        end

        @call_id += 1

        nil
      end

      # Parse a response and process the security context, if `:auth_level` is either RPC_C_AUTHN_LEVEL_PKT_INTEGRITY or RPC_C_AUTHN_LEVEL_PKT_PRIVACY
      #
      # @param raw_data [String] the Response packet as a binary string
      # @param opts [Hash] the authenticaiton options: `:auth_type` and `:auth_level`
      def dcerpc_response_from_raw_response(raw_data, opts = {})
        dcerpc_response = RubySMB::Dcerpc::Response.read(raw_data)
        unless dcerpc_response.pdu_header.ptype == RubySMB::Dcerpc::PTypes::RESPONSE
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Not a Response packet"
        end

        if opts[:auth_level] && [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY].include?(opts[:auth_level])
          handle_integrity_privacy(dcerpc_response, opts)
        end

        dcerpc_response
      rescue IOError
        raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the DCERPC response"
      end
    end
  end
end

