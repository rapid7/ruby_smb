module RubySMB
  # module containing methods required for using the [GSS-API](http://www.rfc-editor.org/rfc/rfc2743.txt)
  # for Secure Protected Negotiation(SPNEGO) in SMB Authentication.
  module Gss
    OID_SPNEGO = OpenSSL::ASN1::ObjectId.new('1.3.6.1.5.5.2')
    OID_NEGOEX = OpenSSL::ASN1::ObjectId.new('1.3.6.1.4.1.311.2.2.30')
    OID_NTLMSSP = OpenSSL::ASN1::ObjectId.new('1.3.6.1.4.1.311.2.2.10')

    # Allow safe navigation of a decoded ASN.1 data structure. Similar to Ruby's
    # builtin Hash#dig method but using the #value attribute of each ASN object.
    #
    # @param asn The ASN object to apply the traversal path on.
    # @param [Array] path The path to traverse, each element is passed to the
    #   ASN object's #value's #[] operator.
    def self.asn1dig(asn, *path)
      path.each do |part|
        return nil unless asn&.value
        asn = asn.value[part]
      end

      asn
    end

    # Cargo culted from Rex. Hacked Together ASN1 encoding that works for our GSS purposes
    # @todo Document these magic numbers
    def self.asn1encode(str = '')
      # If the high bit of the first byte is 1, it contains the number of
      # length bytes that follow
      case str.length
      when 0..0x7F
        encoded_string = [str.length].pack('C') + str
      when 0x80..0xFF
        encoded_string = [0x81, str.length].pack('CC') + str
      when 0x100..0xFFFF
        encoded_string = [0x82, str.length].pack('Cn') + str
      when  0x10000..0xffffff
        encoded_string = [0x83, str.length >> 16, str.length & 0xFFFF].pack('CCn') + str
      when  0x1000000..0xffffffff
        encoded_string = [0x84, str.length].pack('CN') + str
      else
        raise RubySMB::Error::ASN1Encoding, "Source string is too long. Size is #{str.length}"
      end
      encoded_string
    end

    # Create a GSS Security Blob of an NTLM Type 1 Message.
    # This code has been cargo culted and needs to be researched
    # and refactored into something better later.
    def self.gss_type1(type1)
      OpenSSL::ASN1::ASN1Data.new([
        OID_SPNEGO,
        OpenSSL::ASN1::ASN1Data.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ASN1Data.new([
              OpenSSL::ASN1::Sequence.new([
                OID_NTLMSSP
              ])
            ], 0, :CONTEXT_SPECIFIC),
            OpenSSL::ASN1::ASN1Data.new([
              OpenSSL::ASN1::OctetString.new(type1)
            ], 2, :CONTEXT_SPECIFIC)
          ])
        ], 0, :CONTEXT_SPECIFIC)
      ], 0, :APPLICATION).to_der
    end

    # Create a GSS Security Blob of an NTLM Type 2 Message.
    # This code has been cargo culted and needs to be researched
    # and refactored into something better later.
    def self.gss_type2(type2)
      OpenSSL::ASN1::ASN1Data.new([
       OpenSSL::ASN1::Sequence.new([
         OpenSSL::ASN1::ASN1Data.new([
           OpenSSL::ASN1::Enumerated.new(OpenSSL::BN.new(1))
         ], 0, :CONTEXT_SPECIFIC),
         OpenSSL::ASN1::ASN1Data.new([
           OID_NTLMSSP
         ], 1, :CONTEXT_SPECIFIC),
         OpenSSL::ASN1::ASN1Data.new([
           OpenSSL::ASN1::OctetString.new(type2)
         ], 2, :CONTEXT_SPECIFIC)
       ])
      ], 1, :CONTEXT_SPECIFIC).to_der
    end

    # Create a GSS Security Blob of an NTLM Type 3 Message.
    # This code has been cargo culted and needs to be researched
    # and refactored into something better later.
    def self.gss_type3(type3)
      OpenSSL::ASN1::ASN1Data.new([
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ASN1Data.new([
            OpenSSL::ASN1::OctetString.new(type3)
          ], 2, :CONTEXT_SPECIFIC)
        ])
      ], 1, :CONTEXT_SPECIFIC).to_der
    end
  end
end
