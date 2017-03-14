module RubySMB

  # Represents an SMB client capable of talking to SMB1 or SMB2 servers and handling
  # all end-user client functionality.
  class Client
    require 'ruby_smb/client/negotiation'

    include RubySMB::Client::Negotiation

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

    # The username to authenticate with
    # @!attribute [rw] username
    #   @return [String]
    attr_accessor :username

    # @param dispatcher [RubySMB::Dispacther::Socket] the packet dispatcher to use
    # @param smb1 [Boolean] whether or not to enable SMB1 support
    # @param smb2 [Boolean] whether or not to enable SMB2 support
    def initialize(dispatcher, smb1: true, smb2: true, username:,password:, domain:nil, local_workstation:'')
      raise ArgumentError, 'No Dispatcher provided' unless dispatcher.kind_of? RubySMB::Dispatcher::Base
      if smb1 == false && smb2 == false
        raise ArgumentError, 'You must enable at least one Protocol'
      end
      @dispatcher        = dispatcher
      @domain            = domain
      @local_workstation = local_workstation
      @password          = password.encode("utf-8")
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

    # Sends the {RubySMB::SMB1::Packet::SessionSetupRequest} packet and
    # receives the response.
    #
    # @return [String] the binary string response from the server
    def smb1_ntlmssp_negotiate
      packet = smb1_ntlmssp_negotiate_packet
      dispatcher.send_packet(packet)
      dispatcher.recv_packet
    end

    # Creates the {RubySMB::SMB1::Packet::SessionSetupRequest} packet
    # for the first part of the NTLMSSP 4-way hnadshake. This packet
    # initializes negotiations for the NTLMSSP authentication
    #
    # @return [RubySMB::SMB1::Packet::SessionSetupRequest] the first authentication packet to send
    def smb1_ntlmssp_negotiate_packet
      type1_message = ntlm_client.init_context
      packet = RubySMB::SMB1::Packet::SessionSetupRequest.new
      packet.set_type1_blob(type1_message.serialize)
      packet.parameter_block.max_buffer_size = 4356
      packet.parameter_block.max_mpx_count = 50
      packet.smb_header.flags2.extended_security = 1
      packet
    end

    # Takes the raw binary string and returns a {RubySMB::SMB1::Packet::SessionSetupResponse}
    def smb1_ntlmssp_challenge_packet(raw_response)
      packet = RubySMB::SMB1::Packet::SessionSetupResponse.read(raw_response)
      status_code = WindowsError::NTStatus.find_by_retval(packet.smb_header.nt_status.value).first

      unless status_code.name == "STATUS_MORE_PROCESSING_REQUIRED"
        raise RubySMB::Error::UnexpectedStatusCode, status_code.to_s
      end

      unless packet.smb_header.command == RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP
        raise RubySMB::Error::InvalidPacket, "Command was #{packet.smb_header.command} and not #{RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP}"
      end
      packet
    end

    # Parses out the NTLM Type 2 Message from a {RubySMB::SMB1::Packet::SessionSetupResponse}
    #
    # @param response_packet [RubySMB::SMB1::Packet::SessionSetupResponse] the response packet to get the NTLM challenge from
    # @return [String] the base64 encoded  NTLM Challenge (Type2 Message) from the response
    def smb1_type2_message(response_packet)
      sec_blob = response_packet.data_block.security_blob
      ntlmssp_offset = sec_blob.index("NTLMSSP")
      type2_blob = sec_blob.slice(ntlmssp_offset..-1)
      [type2_blob].pack("m")
    end



  end
end
