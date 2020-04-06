module RubySMB
  class Client
    # Contains the methods for handling encryption / decryption
    module Encryption
      def smb3_encrypt(data)
        case @dialect
        when '0x0300', '0x0302'
          encryption_key = RubySMB::Crypto::KDF.counter_mode(@session_key, "SMB2AESCCM\x00", "ServerIn \x00")
        when '0x0311'
          encryption_key = RubySMB::Crypto::KDF.counter_mode(@session_key, "SMBC2SCipherKey\x00", @preauth_integrity_hash_value)
        else
          raise RuntimeError.new('Dialect is incompatible with SMBv3 encryption')
        end

        puts "Encryption key = #{encryption_key.each_byte.map {|e| '%02x' % e}.join}"
        th = RubySMB::SMB2::Packet::TransformHeader.new(flags: 1, session_id: @session_id)
        th.encrypt(data, encryption_key, algorithm: @encryption_algorithm)
        th
      end

      def smb3_decrypt(th)
        case @dialect
        when '0x0300', '0x0302'
          decryption_key = RubySMB::Crypto::KDF.counter_mode(@session_key, "SMB2AESCCM\x00", "ServerOut\x00")
        when '0x0311'
          decryption_key = RubySMB::Crypto::KDF.counter_mode(@session_key, "SMBS2CCipherKey\x00", @preauth_integrity_hash_value)
        else
          raise RuntimeError.new('Dialect is incompatible with SMBv3 decryption')
        end

        puts "Decryption key = #{decryption_key.each_byte.map {|e| '%02x' % e}.join}"
        th.decrypt(decryption_key, algorithm: @encryption_algorithm)
      end
    end
  end
end
