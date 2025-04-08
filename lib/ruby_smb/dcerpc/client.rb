module RubySMB
  module Dcerpc

    # Represents DCERPC SMB client capable of talking to an RPC endpoint in stand-alone.
    class Client
      require 'bindata'
      require 'windows_error'
      require 'ruby_smb/ntlm'
      require 'ruby_smb/dcerpc'
      require 'ruby_smb/gss'
      require 'ruby_smb/peer_info'

      include Dcerpc
      include PeerInfo

      # The default maximum size of a RPC message that the Client accepts (in bytes)
      MAX_BUFFER_SIZE = 64512
      # The read timeout when receiving packets.
      READ_TIMEOUT = 30
      # The default Endpoint Mapper port
      ENDPOINT_MAPPER_PORT = 135

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
        @username          = username
        @password          = password
        @max_buffer_size   = MAX_BUFFER_SIZE
        @call_id           = 1
        @ctx_id            = 0
        @auth_ctx_id_base  = rand(0xFFFFFFFF)

        unless username.empty? && password.empty?
          @ntlm_client = RubySMB::NTLM::Client.new(
            @username,
            @password,
            workstation: @local_workstation,
            domain: @domain,
            flags: ntlm_flags
          )
        end
      end

      # Connect to the RPC endpoint. If a TCP socket was not provided, it takes
      # care of asking the Endpoint Mapper Interface the port used by the given
      # endpoint provided in #initialize and connect a TCP socket
      #
      # @param port [Integer] An optional port number to connect to. If
      #   provided, it will not ask the Endpoint Mapper Interface for a port
      #   number.
      # @return [TcpSocket] The connected TCP socket
      def connect(port: nil)
        return if @tcp_socket

        unless port
          if @endpoint == Epm
            port = ENDPOINT_MAPPER_PORT
          else
            epm_client = Client.new(@host, Epm, read_timeout: @read_timeout)
            epm_client.connect
            epm_client.bind
            begin
              towers = epm_client.ept_map_endpoint(@endpoint)
            rescue RubySMB::Dcerpc::Error::DcerpcError => e
              e.message.prepend(
                "Cannot resolve the remote port number for endpoint #{@endpoint::UUID}. "\
                "Set @tcp_socket parameter to specify the service port number and bypass "\
                "EPM port resolution. Error: "
              )
              raise e
            end

            port = towers.first[:port]
          end
        end

        @tcp_socket = TCPSocket.new(@host, port)
      end

      # Close the TCP Socket
      def close
        @tcp_socket.close if @tcp_socket && !@tcp_socket.closed?
      end

      def process_ntlm_type2(type2_message)
        auth3 = super
        challenge_message = @ntlm_client.session.challenge_message
        store_target_info(challenge_message.target_info) if challenge_message.has_flag?(:TARGET_INFO)
        @os_version = extract_os_version(challenge_message.os_version.to_s) unless challenge_message.os_version.empty?
        auth3
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
          # Per the spec (MS_RPCE 2.2.2.11): start of the trailer should be a multiple of 16 bytes offset from the start of the stub
          valid_offset = (((dcerpc_req.sec_trailer.abs_offset - dcerpc_req.stub.abs_offset) % 16))
          valid_auth_pad = (dcerpc_req.sec_trailer.auth_pad_length == dcerpc_req.auth_pad.length)
          raise Error::InvalidPacket unless valid_offset == 0 && valid_auth_pad
        end

        send_packet(dcerpc_req)

        dcerpc_res = recv_struct(Response)
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
          dcerpc_res = recv_struct(Response)

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

      # Receive a packet from the remote host and parse it according to `struct`
      #
      # @param struct [Class] the structure class to parse the response with
      # @raise [Error::CommunicationError] if socket-related error occurs
      def recv_struct(struct)
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

    end
  end
end

