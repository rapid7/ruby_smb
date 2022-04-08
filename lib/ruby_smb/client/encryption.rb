module RubySMB
  class Client
    # Contains the methods for handling encryption / decryption
    module Encryption
      def smb3_encrypt(data)
        unless @client_encryption_key
          key_bit_len = OpenSSL::Cipher.new(@encryption_algorithm).key_len * 8

          case @dialect
          when '0x0300', '0x0302'
            @client_encryption_key = RubySMB::Crypto::KDF.counter_mode(
              @session_key,
              "SMB2AESCCM\x00",
              "ServerIn \x00",
              length: key_bit_len
            )
          when '0x0311'
            @client_encryption_key = RubySMB::Crypto::KDF.counter_mode(
              @session_key,
              "SMBC2SCipherKey\x00",
              @preauth_integrity_hash_value,
              length: key_bit_len
            )
          else
            raise RubySMB::Error::EncryptionError.new('Dialect is incompatible with SMBv3 encryption')
          end
          ######
          # DEBUG
          #puts "Client encryption key = #{@client_encryption_key.each_byte.map {|e| '%02x' % e}.join}"
          ######
        end

        th = RubySMB::SMB2::Packet::TransformHeader.new(flags: 1, session_id: @session_id)
        th.encrypt(data, @client_encryption_key, algorithm: @encryption_algorithm)
        th
      end

      def smb3_decrypt(th)
        unless @server_encryption_key
          key_bit_len = OpenSSL::Cipher.new(@encryption_algorithm).key_len * 8

          case @dialect
          when '0x0300', '0x0302'
            @server_encryption_key = RubySMB::Crypto::KDF.counter_mode(
              @session_key,
              "SMB2AESCCM\x00",
              "ServerOut\x00",
              length: key_bit_len
            )
          when '0x0311'
            @server_encryption_key = RubySMB::Crypto::KDF.counter_mode(
              @session_key,
              "SMBS2CCipherKey\x00",
              @preauth_integrity_hash_value,
              length: key_bit_len
            )
          else
            raise RubySMB::Error::EncryptionError.new('Dialect is incompatible with SMBv3 decryption')
          end
          ######
          # DEBUG
          #puts "Server encryption key = #{@server_encryption_key.each_byte.map {|e| '%02x' % e}.join}"
          ######
        end

        th.decrypt(@server_encryption_key, algorithm: @encryption_algorithm)
      end
    end
  end
end
