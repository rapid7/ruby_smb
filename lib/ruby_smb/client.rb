module RubySMB

  # Represents an SMB client capable of talking to SMB1 or SMB2 servers and handling
  # all end-user client functionality.
  class Client

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

    # Whether or not the Client should support SMB1
    # @!attribute [rw] smb1
    #   @return [Boolean]
    attr_accessor :smb1

    # Whether or not the Client should support SMB2
    # @!attribute [rw] smb2
    #   @return [Boolean]
    attr_accessor :smb2

    # @param dispatcher [RubySMB::Dispacther::Socket] the packet dispatcher to use
    # @param smb1 [Boolean] whether or not to enable SMB1 support
    # @param smb2 [Boolean] whether or not to enable SMB2 support
    def initialize(dispatcher, smb1: true, smb2: true)
      raise ArgumentError, 'No Dispatcher provided' unless dispatcher.kind_of? RubySMB::Dispatcher::Base
      if smb1 == false && smb2 == false
        raise ArgumentError, 'You must enable at least one Protocol'
      end
      @dispatcher = dispatcher
      @smb1       = smb1
      @smb2       = smb2
    end

    def negotiate

    end

    # Creates and dispatches the first Negotiate Request Packet and
    # returns the raw response data.
    #
    # @return [String] the raw binary string containing the response from the server
    def negotiate_request
      if smb1
        request = smb1_negotiate_request
      elsif smb2
        request = smb2_negotiate_request
      end
      dispatcher.send_packet request
      raw_response = dispatcher.recv_packet
    end


    # Create a {RubySMB::SMB1::Packet::NegotiateRequest} packet with the
    # dialects filled in based on the protocol options set on the Client.
    #
    # @return [RubySMB::SMB1::Packet::NegotiateRequest] a completed SMB1 Negotiate Request packet
    def smb1_negotiate_request
      packet = RubySMB::SMB1::Packet::NegotiateRequest.new

      # There is no real good reason to ever send an SMB1 Negotiate packet
      # to Negotiate strictly SMB2, but the protocol WILL support it
      packet.add_dialect(SMB1_DIALECT_SMB1_DEFAULT) if smb1
      packet.add_dialect(SMB1_DIALECT_SMB2_DEFAULT) if smb2
      packet
    end

    # Create a {RubySMB::SMB2::Packet::NegotiateRequest} packet with
    # the default dialect added. This will never be used when we
    # may want to communicate over SMB1
    #
    # @ return [RubySMB::SMB2::Packet::NegotiateRequest] a completed SMB2 Negotiate Request packet
    def smb2_negotiate_request
      packet = RubySMB::SMB2::Packet::NegotiateRequest.new
      packet.smb2_header.message_id = 1
      packet.add_dialect(SMB2_DIALECT_DEFAULT)
      packet
    end


  end
end
