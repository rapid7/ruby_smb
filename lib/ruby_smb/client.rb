module RubySMB

  # Represents an SMB client capable of talking to SMB1 or SMB2 servers and handling
  # all end-user client functionality.
  class Client
    require 'ruby_smb/client/negotiation'
    require 'ruby_smb/client/authentication'
    require 'ruby_smb/client/signing'

    include RubySMB::Client::Negotiation
    include RubySMB::Client::Authentication
    include RubySMB::Client::Signing

    # The Default SMB1 Dialect string used in an SMB1 Negotiate Request
    SMB1_DIALECT_SMB1_DEFAULT = "NT LM 0.12"
    # The Default SMB2 Dialect string used in an SMB1 Negotiate Request
    SMB1_DIALECT_SMB2_DEFAULT = "SMB 2.002"
    # Dialect value for SMB2 Default (Version 2.02)
    SMB2_DIALECT_DEFAULT = 0x0202


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
    #   @return [String]
    attr_accessor :user_id

    # @param dispatcher [RubySMB::Dispacther::Socket] the packet dispatcher to use
    # @param smb1 [Boolean] whether or not to enable SMB1 support
    # @param smb2 [Boolean] whether or not to enable SMB2 support
    def initialize(dispatcher, smb1: true, smb2: true, username:,password:, domain:'.', local_workstation:'WORKSTATION')
      raise ArgumentError, 'No Dispatcher provided' unless dispatcher.kind_of? RubySMB::Dispatcher::Base
      if smb1 == false && smb2 == false
        raise ArgumentError, 'You must enable at least one Protocol'
      end
      @dispatcher        = dispatcher
      @domain            = domain
      @local_workstation = local_workstation
      @password          = password.encode("utf-8")
      @sequence_counter  = 0
      @session_id        = 0x00
      @session_key       = ''
      @signing_required  = false
      @smb1              = smb1
      @smb2              = smb2
      @username          = username.encode("utf-8")

      @ntlm_client = Net::NTLM::Client.new(
        @username,
        @password,
        workstation: @local_workstation,
        domain: @domain
      )

      @smb2_message_id = 0
    end

    # Responsible for handling Authentication and Session Setup for
    # the SMB Client. It returns the final Status code from the authentication
    # exchange.
    #
    # @return [WindowsError::NTStatus] the NTStatus object from the SessionSetup exchange.
    def authenticate
      if self.smb1
        smb1_authenticate
      else
        smb2_authenticate
      end
    end

    # Handles the entire SMB Multi-Protocol Negotiation from the
    # Client to the Server. It sets state on the client appropriate
    # to the protocol and capabilites negotiated during the exchange.
    #
    # @return [void]
    def negotiate
      raw_response    = negotiate_request
      response_packet = negotiate_response(raw_response)
      parse_negotiate_response(response_packet)
    end

    # Sends a packet and receives the raw response through the Dispatcher.
    # It will also sign the packet if neccessary.
    #
    # @param packet [RubySMB::GenericPacket] the request to be sent
    # @return [String] the raw response data received
    def send_recv(packet)
      case packet.packet_smb_version
        when 'SMB1'
          packet = smb1_sign(packet)
        when 'SMB2'
          packet = smb2_sign(packet)
        else
          packet = packet
      end
      dispatcher.send_packet(packet)
      raw_response = dispatcher.recv_packet
      if self.sequence_counter > 0
        self.sequence_counter += 1
      end
      raw_response
    end

    private




  end
end
