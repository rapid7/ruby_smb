module RubySMB
  # Represents an SMB client capable of talking to SMB1 or SMB2 servers and handling
  # all end-user client functionality.
  class Client
    require 'ruby_smb/ntlm'
    require 'ruby_smb/signing'
    require 'ruby_smb/client/negotiation'
    require 'ruby_smb/client/authentication'
    require 'ruby_smb/client/tree_connect'
    require 'ruby_smb/client/echo'
    require 'ruby_smb/client/utils'
    require 'ruby_smb/client/winreg'
    require 'ruby_smb/client/encryption'

    include RubySMB::Signing
    include RubySMB::Client::Negotiation
    include RubySMB::Client::Authentication
    include RubySMB::Client::TreeConnect
    include RubySMB::Client::Echo
    include RubySMB::Client::Utils
    include RubySMB::Client::Winreg
    include RubySMB::Client::Encryption

    # The Default SMB1 Dialect string used in an SMB1 Negotiate Request
    SMB1_DIALECT_SMB1_DEFAULT = 'NT LM 0.12'.freeze
    # The Default SMB2 Dialect string used in an SMB1 Negotiate Request
    SMB1_DIALECT_SMB2_DEFAULT = 'SMB 2.002'.freeze
    # The SMB2 wildcard revision number Dialect string used in an SMB1 Negotiate Request
    # It indicates that the server implements SMB 2.1 or future dialect revisions
    # Note that this must be used for SMB3
    SMB1_DIALECT_SMB2_WILDCARD = 'SMB 2.???'.freeze

    SMB2_DIALECT_0202 = '0x0202'.freeze
    SMB2_DIALECT_0210 = '0x0210'.freeze
    SMB2_DIALECT_0300  = '0x0300'.freeze
    SMB2_DIALECT_0302  = '0x0302'.freeze
    SMB2_DIALECT_0311  = '0x0311'.freeze

    # Dialect values for SMB2
    SMB2_DIALECT_DEFAULT = [
      SMB2_DIALECT_0202,
      SMB2_DIALECT_0210,
    ].freeze

    # Dialect values for SMB3
    SMB3_DIALECT_DEFAULT = [
      SMB2_DIALECT_0300,
      SMB2_DIALECT_0302,
      SMB2_DIALECT_0311
    ].freeze

    # The default maximum size of a SMB message that the Client accepts (in bytes)
    MAX_BUFFER_SIZE = 64512
    # The default maximum size of a SMB message that the Server accepts (in bytes)
    SERVER_MAX_BUFFER_SIZE = 4356

    # The dispatcher responsible for sending packets
    # @!attribute [rw] dispatcher
    #   @return [RubySMB::Dispatcher::Socket]
    attr_accessor :dispatcher

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

    # The password to authenticate with
    # @!attribute [rw] password
    #   @return [String]
    attr_accessor :password

    # The Native OS of the Peer/Server.
    # Currently only available with SMB1.
    # @!attribute [rw] peer_native_os
    #   @return [String]
    attr_accessor :peer_native_os

    # The Native LAN Manager of the Peer/Server.
    # Currently only available with SMB1.
    # @!attribute [rw] peer_native_lm
    #   @return [String]
    attr_accessor :peer_native_lm

    # The Primary Domain of the Peer/Server.
    # Currently only available with SMB1 and only when authentiation
    # without NTLMSSP is used.
    # @!attribute [rw] primary_domain
    #   @return [String]
    attr_accessor :primary_domain

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

    # The negotiated dialect.
    # @!attribute [rw] dialect
    #   @return [Integer]
    attr_accessor :dialect

    # The Sequence Counter used for SMB1 Signing.
    # It tracks the number of packets both sent and received
    # since the NTLM session was initialized with the Challenge.
    # @!attribute [rw] sequence_counter
    #   @return [Integer]
    attr_accessor :sequence_counter

    # The current Session ID setup by authentication
    # @!attribute [rw] session_id
    #   @return [Integer]
    attr_accessor :session_id

    # Whether or not the current session has the guest flag set
    # @!attribute [rw] session_is_guest
    #   @return [Boolean]
    attr_accessor :session_is_guest

    # Whether or not the Server requires signing
    # @!attribute [rw] signing_enabled
    #   @return [Boolean]
    attr_accessor :signing_required

    # Whether or not the Client should support SMB1
    # @!attribute [rw] smb1
    #   @return [Boolean]
    attr_accessor :smb1

    # Whether or not the Client should support SMB2
    # @!attribute [rw] smb2
    #   @return [Boolean]
    attr_accessor :smb2

    # Whether or not the Client should support SMB3
    # @!attribute [rw] smb3
    #   @return [Boolean]
    attr_accessor :smb3

    #  Tracks the current SMB2 Message ID that keeps communication in sync
    # @!attribute [rw] smb2_message_id
    #   @return [Integer]
    attr_accessor :smb2_message_id

    # The username to authenticate with
    # @!attribute [rw] username
    #   @return [String]
    attr_accessor :username

    # The UID set in SMB1
    # @!attribute [rw] user_id
    #   @return [Integer]
    attr_accessor :user_id

    # The Process ID set in SMB1
    # It is randomly generated during the client initialization, but can
    # be modified using the accessor.
    # @!attribute [rw] pid
    #   @return [Integer]
    attr_accessor :pid

    # The maximum size SMB message that the Client accepts (in bytes)
    # The default value is equal to {MAX_BUFFER_SIZE}.
    # @!attribute [rw] max_buffer_size
    #   @return [Integer]
    attr_accessor :max_buffer_size

    # The maximum size SMB message that the Server accepts (in bytes)
    # The default value is small by default
    # @!attribute [rw] max_buffer_size
    #   @return [Integer]
    attr_accessor :server_max_buffer_size

    # The maximum size SMB2 write request that the Server accepts (in bytes)
    # @!attribute [rw] server_max_write_size
    #   @return [Integer]
    attr_accessor :server_max_write_size

    # The maximum size SMB2 read request that the Server accepts (in bytes)
    # @!attribute [rw] server_max_read_size
    #   @return [Integer]
    attr_accessor :server_max_read_size

    # The maximum size SMB2 transaction that the Server accepts (in bytes)
    # For transactions that are not a read or write request
    # @!attribute [rw] server_max_transact_size
    #   @return [Integer]
    attr_accessor :server_max_transact_size

    # The algorithm to compute the preauthentication integrity hash (SMB 3.1.1).
    # @!attribute [rw] preauth_integrity_hash_algorithm
    #   @return [String]
    attr_accessor :preauth_integrity_hash_algorithm

    # The preauthentication integrity hash value (SMB 3.1.1).
    # @!attribute [rw] preauth_integrity_hash_value
    #   @return [String]
    attr_accessor :preauth_integrity_hash_value

    # The algorithm for encryption (SMB 3.x).
    # @!attribute [rw] encryption_algorithm
    #   @return [String]
    attr_accessor :encryption_algorithm

    # The client encryption key (SMB 3.x).
    # @!attribute [rw] client_encryption_key
    #   @return [String]
    attr_accessor :client_encryption_key

    # The server encryption key (SMB 3.x).
    # @!attribute [rw] server_encryption_key
    #   @return [String]
    attr_accessor :server_encryption_key

    # Whether or not the whole session needs to be encrypted (SMB 3.x)
    # @!attribute [rw] session_encrypt_data
    #   @return [Boolean]
    attr_accessor :session_encrypt_data

    # The encryption algorithms supported by the server (SMB 3.x).
    # @!attribute [rw] server_encryption_algorithms
    #   @return [Array<Integer>] list of supported encryption algorithms
    #     (constants defined in RubySMB::SMB2::EncryptionCapabilities)
    attr_accessor :server_encryption_algorithms

    # The compression algorithms supported by the server (SMB 3.x).
    # @!attribute [rw] server_compression_algorithms
    #   @return [Array<Integer>] list of supported compression algorithms
    #     (constants defined in RubySMB::SMB2::CompressionCapabilities)
    attr_accessor :server_compression_algorithms

    # The GUID of the server (SMB 2.x and 3.x).
    # @!attribute [rw] server_guid
    #   @return [String]
    attr_accessor :server_guid

    # The server's start time if it is reported as part of the negotiation
    # process (SMB 2.x and 3.x). This value is nil if the server does not report
    # it (reports a value of 0).
    # @!attribute [rw] server_start_time
    #   @return [Time] the time that the server reports that it was started at
    attr_accessor :server_start_time

    # The server's current time if it is reported as part of the negotiation
    # process (SMB 2.x and 3.x). This value is nil if the server does not report
    # it (reports a value of 0).
    # @!attribute [rw] server_system_time
    #   @return [Time] the time that the server reports as current
    attr_accessor :server_system_time

    # The SMB version that has been successfully negotiated. This value is only
    # set after the NEGOTIATE handshake has been performed.
    # @!attribute [rw] negotiated_smb_version
    #   @return [Integer] the negotiated SMB version
    attr_accessor :negotiated_smb_version

    # Whether or not the server supports multi-credit operations. It is
    # reported by the LARGE_MTU capabiliy as part of the negotiation process
    # (SMB 2.x and 3.x).
    # @!attribute [rw] server_supports_multi_credit
    #   @return [Boolean] true if the server supports multi-credit operations,
    #   false otherwise
    attr_accessor :server_supports_multi_credit

    # @param dispatcher [RubySMB::Dispatcher::Socket] the packet dispatcher to use
    # @param smb1 [Boolean] whether or not to enable SMB1 support
    # @param smb2 [Boolean] whether or not to enable SMB2 support
    # @param smb3 [Boolean] whether or not to enable SMB3 support
    def initialize(dispatcher, smb1: true, smb2: true, smb3: true, username:, password:, domain: '.',
                   local_workstation: 'WORKSTATION', always_encrypt: true, ntlm_flags: NTLM::DEFAULT_CLIENT_FLAGS)
      raise ArgumentError, 'No Dispatcher provided' unless dispatcher.is_a? RubySMB::Dispatcher::Base
      if smb1 == false && smb2 == false && smb3 == false
        raise ArgumentError, 'You must enable at least one Protocol'
      end
      @dispatcher        = dispatcher
      @pid               = rand(0xFFFF)
      @domain            = domain
      @local_workstation = local_workstation
      @password          = password.encode('utf-8') || ''.encode('utf-8')
      @sequence_counter  = 0
      @session_id        = 0x00
      @session_key       = ''
      @session_is_guest  = false
      @signing_required  = false
      @smb1              = smb1
      @smb2              = smb2
      @smb3              = smb3
      @username          = username.encode('utf-8') || ''.encode('utf-8')
      @max_buffer_size   = MAX_BUFFER_SIZE
      # These sizes will be modified during negotiation
      @server_max_buffer_size = SERVER_MAX_BUFFER_SIZE
      @server_max_read_size   = RubySMB::SMB2::File::MAX_PACKET_SIZE
      @server_max_write_size  = RubySMB::SMB2::File::MAX_PACKET_SIZE
      @server_max_transact_size = RubySMB::SMB2::File::MAX_PACKET_SIZE
      @server_supports_multi_credit = false

      # SMB 3.x options
      # this merely initializes the default value for session encryption, it may be changed as necessary when a
      # session setup response is received
      @session_encrypt_data = always_encrypt

      @ntlm_client = RubySMB::NTLM::Client.new(
        @username,
        @password,
        workstation: @local_workstation,
        domain: @domain,
        flags: ntlm_flags
      )

      @tree_connects = []
      @open_files = {}

      @smb2_message_id = 0
    end

    # Logs off any currently open session on the server
    # and closes the TCP socket connection.
    #
    # @return [void]
    def disconnect!
      begin
        logoff!
      rescue
        wipe_state!
      end
      dispatcher.tcp_socket.close
    end

    # Sends an Echo request to the server and returns the
    # NTStatus of the last response packet received.
    #
    # @param echo [Integer] the number of times the server should echo (ignored in SMB2)
    # @param data [String] the data the server should echo back (ignored in SMB2)
    # @return [WindowsError::ErrorCode] the NTStatus of the last response received
    def echo(count: 1, data: '')
      response = if smb2 || smb3
                   smb2_echo
                 else
                   smb1_echo(count: count, data: data)
                 end
      response.status_code
    end

    # Sets the message id field in an SMB2 packet's
    # header to the one tracked by the client. It then increments
    # the counter on the client.
    #
    # @param packet [RubySMB::GenericPacket] the packet to set the message id for
    # @return [RubySMB::GenericPacket] the modified packet
    def increment_smb_message_id(packet)
      packet.smb2_header.message_id = self.smb2_message_id
      self.smb2_message_id += 1
      packet
    end

    # Performs protocol negotiation and session setup. It defaults to using
    # the credentials supplied during initialization, but can take a new set of credentials if needed.
    def login(username: self.username, password: self.password,
              domain: self.domain, local_workstation: self.local_workstation,
              ntlm_flags: NTLM::DEFAULT_CLIENT_FLAGS)
      negotiate
      session_setup(username, password, domain,
                    local_workstation: local_workstation,
                    ntlm_flags: ntlm_flags)
    end

    def session_setup(user, pass, domain, do_recv=true,
                      local_workstation: self.local_workstation, ntlm_flags: NTLM::DEFAULT_CLIENT_FLAGS)
      @domain            = domain
      @local_workstation = local_workstation
      @password          = pass.encode('utf-8') || ''.encode('utf-8')
      @username          = user.encode('utf-8') || ''.encode('utf-8')

      @ntlm_client = RubySMB::NTLM::Client.new(
          @username,
          @password,
          workstation: @local_workstation,
          domain: @domain,
          flags: ntlm_flags
      )

      authenticate
    end

    # Sends a LOGOFF command to the remote server to terminate the session
    #
    # @return [WindowsError::ErrorCode] the NTStatus of the response
    # @raise [RubySMB::Error::InvalidPacket] if the response packet is not a LogoffResponse packet
    def logoff!
      if smb2 || smb3
        request      = RubySMB::SMB2::Packet::LogoffRequest.new
        raw_response = send_recv(request)
        response     = RubySMB::SMB2::Packet::LogoffResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::LogoffResponse::COMMAND,
            packet:         response
          )
        end
      else
        request      = RubySMB::SMB1::Packet::LogoffRequest.new
        raw_response = send_recv(request)
        response     = RubySMB::SMB1::Packet::LogoffResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::LogoffResponse::COMMAND,
            packet:         response
          )
        end
      end
      wipe_state!
      response.status_code
    end

    # Sends a packet and receives the raw response through the Dispatcher.
    # It will also sign the packet if necessary.
    #
    # @param packet [RubySMB::GenericPacket] the request to be sent
    # @param encrypt [Boolean] true if encryption has to be enabled for this transaction
    #   (note that if @session_encrypt_data is set, encryption will be enabled
    #   regardless of this parameter value)
    # @return [String] the raw response data received
    def send_recv(packet, encrypt: false)
      version = packet.packet_smb_version
      case version
      when 'SMB1'
        packet.smb_header.uid = self.user_id if self.user_id
        packet.smb_header.pid_low = self.pid if self.pid
        packet = smb1_sign(packet) if signing_required && !session_key.empty?
        self.sequence_counter += 1
      when 'SMB2'
        packet = increment_smb_message_id(packet)
        packet.smb2_header.session_id = session_id
        unless packet.is_a?(RubySMB::SMB2::Packet::SessionSetupRequest) || session_key.empty?
          if self.smb2 && signing_required
            packet = smb2_sign(packet)
          elsif self.smb3
            # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/652e0c14-5014-4470-999d-b174d7b2da87
            if @dialect == '0x0311' && (signing_required || (!@session_is_guest && packet.is_a?(RubySMB::SMB2::Packet::TreeConnectRequest)))
              packet = smb3_sign(packet)
            elsif signing_required
              packet = smb3_sign(packet)
            end
          end
        end
      else
        packet = packet
      end

      encrypt_data = false
      if can_be_encrypted?(packet) && encryption_supported? && (@session_encrypt_data || encrypt)
        encrypt_data = true
      end
      send_packet(packet, encrypt: encrypt_data)
      raw_response = recv_packet(encrypt: encrypt_data)
      smb2_header = nil
      loop do
        smb2_header = RubySMB::SMB2::SMB2Header.read(raw_response)
        break unless is_status_pending?(smb2_header)
        sleep 1
        raw_response = recv_packet(encrypt: encrypt_data)
      rescue IOError
        # We're expecting an SMB2 packet, but the server sent an SMB1 packet
        # instead. This behavior has been observed with older versions of Samba
        # when something goes wrong on the server side. So, we just ignore it
        # and expect the caller to handle this wrong response packet.
        break
      end unless version == 'SMB1'

      self.sequence_counter += 1
      # update the SMB2 message ID according to the received Credit Charged
      self.smb2_message_id += smb2_header.credit_charge - 1 if smb2_header && self.server_supports_multi_credit
      raw_response
    end

    # Check if the response is an asynchronous operation with STATUS_PENDING
    # status code.
    #
    # @param smb2_header [String] the response packet SMB2 header
    # @return [Boolean] true if it is a status pending operation, false otherwise
    def is_status_pending?(smb2_header)
      value = smb2_header.nt_status.value
      status_code = WindowsError::NTStatus.find_by_retval(value).first
      status_code == WindowsError::NTStatus::STATUS_PENDING &&
        smb2_header.flags.async_command == 1
    end

    # Check if the request packet can be encrypted. Per the SMB2 spec,
    # SessionSetupRequest and NegotiateRequest must not be encrypted.
    #
    # @param packet [RubySMB::GenericPacket] the request packet
    # @return [Boolean] true if the packet can be encrypted
    def can_be_encrypted?(packet)
      return false if packet.packet_smb_version == 'SMB1'
      [RubySMB::SMB2::Packet::SessionSetupRequest, RubySMB::SMB2::Packet::NegotiateRequest].none? do |klass|
        packet.is_a?(klass)
      end
    end

    # Check if the current dialect supports encryption.
    #
    # @return [Boolean] true if encryption is supported
    def encryption_supported?
      ['0x0300', '0x0302', '0x0311'].include?(@dialect)
    end

    # Encrypt (if required) and send a packet.
    #
    # @param encrypt [Boolean] true if the packet should be encrypted, false
    #   otherwise
    def send_packet(packet, encrypt: false)
      if encrypt
        begin
          packet = smb3_encrypt(packet.to_binary_s)
        rescue RubySMB::Error::RubySMBError => e
          raise RubySMB::Error::EncryptionError, "Error while encrypting #{packet.class.name} packet (SMB #{@dialect}): #{e}"
        end
      end
      dispatcher.send_packet(packet)
    end

    # Receives the raw response through the Dispatcher and decrypt the packet (if required).
    #
    # @param encrypt [Boolean] true if the packet is encrypted, false otherwise
    # @return [String] the raw unencrypted packet
    def recv_packet(encrypt: false)
      begin
        raw_response = dispatcher.recv_packet
      rescue RubySMB::Error::CommunicationError => e
        if encrypt
          raise RubySMB::Error::EncryptionError, "Communication error with the "\
            "remote host: #{e.message}. The server supports encryption but was "\
            "not able to handle the encrypted request."
        else
          raise e
        end
      end
      if encrypt
        begin
          transform_response = RubySMB::SMB2::Packet::TransformHeader.read(raw_response)
        rescue IOError
          raise RubySMB::Error::InvalidPacket, 'Not a SMB2 TransformHeader packet'
        end
        begin
          raw_response = smb3_decrypt(transform_response)
        rescue RubySMB::Error::RubySMBError => e
          raise RubySMB::Error::EncryptionError, "Error while decrypting #{transform_response.class.name} packet (SMB #@dialect}): #{e}"
        end
      end
      raw_response
    end

    # Connects to the supplied share
    #
    # @param share [String] the path to the share in `\\server\share_name` format
    # @return [RubySMB::SMB1::Tree] if talking over SMB1
    # @return [RubySMB::SMB2::Tree] if talking over SMB2
    def tree_connect(share)
      connected_tree = if smb2 || smb3
        smb2_tree_connect(share)
      else
        smb1_tree_connect(share)
      end
      @tree_connects << connected_tree
      connected_tree
    end

    # Returns array of shares
    #
    # @return [Array] of shares
    # @param [String] host
    def net_share_enum_all(host)
      tree = tree_connect("\\\\#{host}\\IPC$")
      named_pipe = tree.open_pipe(filename: "srvsvc", write: true, read: true)
      named_pipe.net_share_enum_all(host)
    end

    # Resets all of the session state on the client, setting it
    # back to scratch. Should only be called when a session is no longer
    # valid.
    #
    # @return [void]
    def wipe_state!
      self.session_id       = 0x00
      self.user_id          = 0x00
      self.session_key      = ''
      self.session_is_guest = false
      self.sequence_counter = 0
      self.smb2_message_id  = 0
      self.client_encryption_key = nil
      self.server_encryption_key = nil
      self.server_supports_multi_credit = false
    end

    # Requests a NetBIOS Session Service using the provided name.
    #
    # @param name [String] the NetBIOS name to request
    # @return [TrueClass] if session request is granted
    # @raise [RubySMB::Error::NetBiosSessionService] if session request is refused
    # @raise [RubySMB::Error::InvalidPacket] if the response packet is not a NBSS packet
    def session_request(name = '*SMBSERVER')
      session_request = session_request_packet(name)
      dispatcher.send_packet(session_request, nbss_header: false)
      raw_response = dispatcher.recv_packet(full_response: true)
      begin
        session_header = RubySMB::Nbss::SessionHeader.read(raw_response)
        if session_header.session_packet_type == RubySMB::Nbss::NEGATIVE_SESSION_RESPONSE
          negative_session_response =  RubySMB::Nbss::NegativeSessionResponse.read(raw_response)
          raise RubySMB::Error::NetBiosSessionService, "Session Request failed: #{negative_session_response.error_msg}"
        end
      rescue IOError
        raise RubySMB::Error::InvalidPacket, 'Not a NBSS packet'
      end

      return true
    end

    # Crafts the NetBIOS SessionRequest packet to be sent for session request operations.
    #
    # @param name [String] the NetBIOS name to request
    # @return [RubySMB::Nbss::SessionRequest] the SessionRequest packet
    def session_request_packet(name = '*SMBSERVER')
      called_name = "#{name.upcase.ljust(15)}\x20"
      calling_name = "#{''.ljust(15)}\x00"

      session_request = RubySMB::Nbss::SessionRequest.new
      session_request.session_header.session_packet_type = RubySMB::Nbss::SESSION_REQUEST
      session_request.called_name  = called_name
      session_request.calling_name = calling_name
      session_request.session_header.stream_protocol_length =
        session_request.num_bytes - session_request.session_header.num_bytes
      session_request
    end

    def update_preauth_hash(data)
      unless @preauth_integrity_hash_algorithm
        raise RubySMB::Error::EncryptionError.new(
          'Cannot compute the Preauth Integrity Hash value: Preauth Integrity Hash Algorithm is nil'
        )
      end
      @preauth_integrity_hash_value = OpenSSL::Digest.digest(
        @preauth_integrity_hash_algorithm,
        @preauth_integrity_hash_value + data.to_binary_s
      )
    end

  end
end
