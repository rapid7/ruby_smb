module RubySMB
  # Contains the methods for handling packet signing
  module Signing
    # The NTLM Session Key used for signing
    # @!attribute [rw] session_key
    #   @return [String]
    attr_accessor :session_key

    # Take an SMB1 packet and sign it.
    #
    # @param packet [RubySMB::GenericPacket] the packet to sign
    # @return [RubySMB::GenericPacket] the signed packet
    def smb1_sign(packet)
      # Pack the Sequence counter into a int64le
      packed_sequence_counter = [@sequence_counter].pack('Q<')
      packet.smb_header.security_features = packed_sequence_counter
      signature = OpenSSL::Digest::MD5.digest(@session_key + packet.to_binary_s)[0, 8]
      packet.smb_header.security_features = signature
      @sequence_counter += 1

      packet
    end

    # Take an SMB2 packet and sign it.
    #
    # @param packet [RubySMB::GenericPacket] the packet to sign
    # @return [RubySMB::GenericPacket] the signed packet
    def smb2_sign(packet)
      Signing::smb2_sign(packet, @session_key)
    end

    def self.smb2_sign(packet, session_key)
      packet.smb2_header.flags.signed = 1
      packet.smb2_header.signature = "\x00" * 16
      hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), session_key, packet.to_binary_s)
      packet.smb2_header.signature = hmac[0, 16]

      packet
    end

    # Take an SMB3 packet and sign it.
    #
    # @param packet [RubySMB::GenericPacket] the packet to sign
    # @return [RubySMB::GenericPacket] the signed packet
    def smb3_sign(packet)
      Signing::smb3_sign(packet, @session_key, @dialect, @preauth_integrity_hash_value)
    end

    def self.smb3_sign(packet, session_key, dialect, preauth_integrity_hash=nil)
      case dialect
      when '0x0300', '0x0302'
        signing_key = Crypto::KDF.counter_mode(session_key, "SMB2AESCMAC\x00", "SmbSign\x00")
      when '0x0311'
        raise ArgumentError.new('the preauth integrity hash is required for the specified dialect') if preauth_integrity_hash.nil?
        signing_key = Crypto::KDF.counter_mode(session_key, "SMBSigningKey\x00", preauth_integrity_hash)
      else
        raise Error::SigningError.new("Dialect #{dialect.inspect} is incompatible with SMBv3 signing")
      end

      packet.smb2_header.flags.signed = 1
      packet.smb2_header.signature = "\x00" * 16
      hmac = OpenSSL::CMAC.digest('AES', signing_key, packet.to_binary_s)
      packet.smb2_header.signature = hmac[0, 16]

      packet
    end
  end
end
