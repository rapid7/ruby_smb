module RubySMB
  # Contains all the RubySMB specific Error classes.
  module Error
    # Base class for RubySMB errors
    class RubySMBError < StandardError; end

    # Raised when there is a length or formatting issue with an ASN1-encoded string
    # @see https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
    # @todo Find an SMB-specific link for ASN1 above
    class ASN1Encoding < RubySMBError; end

    # Raised when there is a problem with communication over NetBios Session Service
    # @see https://wiki.wireshark.org/NetBIOS/NBSS
    class NetBiosSessionService < RubySMBError; end

    # Raised when trying to parse raw binary into a Packet and the data
    # is invalid.
    class InvalidPacket < RubySMBError; end

    # Raised when a response packet has a NTStatus code that was unexpected.
    class UnexpectedStatusCode < RubySMBError; end

    # Raised when an error occurs with the underlying socket.
    class CommunicationError < RubySMBError; end

    # Raised when Protocol Negotiation fails, possibly due to an
    # unsupported protocol.
    class NegotiationFailure < RubySMBError; end

    # Raised when trying to parse raw binary into a BitField and the data
    # is invalid.
    class InvalidBitField < RubySMBError; end
  end
end
