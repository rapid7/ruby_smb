module RubySMB
  # Contains the methods for handling packet signing
  module Signing
    # The NTLM Session Key used for signing
    # @!attribute [rw] session_key
    #   @return [String]
    attr_accessor :session_key

    # Take an SMB1 packet and sign it. This version is an instance method that
    # accesses the necessary values from the object instance.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @return [RubySMB::GenericPacket] the signed packet
    def smb1_sign(packet)
      packet = Signing::smb1_sign(packet, session_key, sequence_counter)
      self.sequence_counter += 1

      packet
    end

    # Take an SMB1 packet and sign it. This version is a module function that
    # requires the necessary values to be explicitly passed to it.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @param [String] session_key The key to use for signing.
    # @param [Integer] sequence_counter The sequence counter of packet to be sent.
    # @return [RubySMB::GenericPacket] the signed packet
    def self.smb1_sign(packet, session_key, sequence_counter)
      # Pack the Sequence counter into a int64le
      packed_sequence_counter = [sequence_counter].pack('Q<')
      packet.smb_header.security_features = packed_sequence_counter
      signature = OpenSSL::Digest::MD5.digest(session_key + packet.to_binary_s)[0, 8]
      packet.smb_header.security_features = signature

      packet
    end

    # Take an SMB2 packet and sign it. This version is an instance method that
    # accesses the necessary values from the object instance.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @return [RubySMB::GenericPacket] the signed packet
    def smb2_sign(packet)
      Signing::smb2_sign(packet, session_key)
    end

    # Take an SMB2 packet and sign it. This version is a module function that
    # requires the necessary values to be explicitly passed to it.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @param [String] session_key The key to use for signing.
    # @return [RubySMB::GenericPacket] the signed packet
    def self.smb2_sign(packet, session_key)
      return packet if session_key.nil? || session_key == ''

      packet.smb2_header.flags.signed = 1
      packet.smb2_header.signature = "\x00" * 16
      hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), session_key, packet.to_binary_s)
      packet.smb2_header.signature = hmac[0, 16]

      packet
    end

    # Take an SMB3 packet and sign it. This version is an instance method that
    # accesses the necessary values from the object instance.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @return [RubySMB::GenericPacket] the signed packet
    def smb3_sign(packet)
      Signing::smb3_sign(packet, @session_key, @dialect, @preauth_integrity_hash_value)
    end

    # Take an SMB3 packet and sign it. This version is a module function that
    # requires the necessary values to be explicitly passed to it.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @param [String] session_key The key to use for signing.
    # @param [String] dialect The SMB3 dialect to sign for.
    # @param [String] preauth_integrity_hash The preauth integrity hash as
    #   required by the 3.1.1 dialect.
    # @return [RubySMB::GenericPacket] the signed packet
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
