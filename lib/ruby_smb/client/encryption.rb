module RubySMB
  class Client
    # Contains the methods for handling encryption / decryption
    module Encryption
      def smb3_0_encrypt(data, session_id, session_key)
        # handle the 3.0 and 3.0.2 dialects
        encryption_key = RubySMB::Crypto::KDF.counter_mode(session_key, "SMB2AESCCM\x00", "ServerIn \x00")

        # in these dialects, flags = 1 means AES-128-CCM
        th = RubySMB::SMB2::Packet::TransformHeader.new(flags: 1, session_id: session_id)
        th.encrypt(data, encryption_key, algorithm: 'AES-128-CCM')
        th
      end

      def smb3_0_decrypt(th, session_key)
        decryption_key = RubySMB::Crypto::KDF.counter_mode(session_key, "SMB2AESCCM\x00", "ServerOut\x00")
        th.decrypt(decryption_key)
      end

      def smb3_1_encrypt(data, session_id, session_key, context)
        # handle the 3.1.1 dialect
        encryption_key = RubySMB::Crypto::KDF.counter_mode(session_key, "SMBC2SCipherKey\x00", context)
        puts "Encryption key = #{encryption_key.each_byte.map {|e| '%02x' % e}.join}"

        # in this dialect, flags = 1 means encrypted
        th = RubySMB::SMB2::Packet::TransformHeader.new(flags: 1, session_id: session_id)
        th.encrypt(data, encryption_key, algorithm: @encryption_algorithm)
        th
      end

      def smb3_1_decrypt(th, session_key, context)
        decryption_key = RubySMB::Crypto::KDF.counter_mode(session_key, "SMBS2CCipherKey\x00", context)
        puts "Decryption key = #{decryption_key.each_byte.map {|e| '%02x' % e}.join}"
        th.decrypt(decryption_key, algorithm: @encryption_algorithm)
      end
    end
  end
end
