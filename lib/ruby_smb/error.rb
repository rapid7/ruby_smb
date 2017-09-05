module RubySMB
  # Contains all the RubySMB specific Error classes.
  module Error
    # Raised when there is a length or formatting issue with an ASN1-encoded string
    # @see https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
    # @todo Find an SMB-specific link for ASN1 above
    class ASN1Encoding < StandardError; end

    # Raised when there is a problem with communication over NetBios Session Service
    # @see https://wiki.wireshark.org/NetBIOS/NBSS
    class NetBiosSessionService < StandardError; end

    # Raised when trying to parse raw binary into a Packet and the data
    # is invalid.
    class InvalidPacket < StandardError; end

    # Raised when a response packet has a NTStatus code that was unexpected.
    class UnexpectedStatusCode < StandardError; end

    # Raised when an error occurs with the underlying socket.
    class CommunicationError < StandardError; end

    # Raised when Protocol Negotiation fails, possibly due to an
    # unsupported protocol.
    class NegotiationFailure < StandardError; end
  end
end
