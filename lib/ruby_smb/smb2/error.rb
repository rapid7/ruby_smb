module RubySmb::Error
  # Raised when there is a length or formatting issue with an ASN1-encoded string
  # @see https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
  # @todo Find an SMB-specific link for ASN1 above
  class ASN1Encoding < Exception; end

  # Raised when there is a problem with communication over NetBios Session Service
  # @see https://wiki.wireshark.org/NetBIOS/NBSS
  class NetBiosSessionService < Exception; end
end
