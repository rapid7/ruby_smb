module RubySMB
  module SMB2
    module Packet
      # An SMB2 TRANSFORM_HEADER Packet as defined in
      # [2.2.41 SMB2 TRANSFORM_HEADER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d6ce2327-a4c9-4793-be66-7b5bad2175fa)
      class TransformHeader < BinData::Record
        endian :little
        hide   :reserved0

        endian           :little
        bit32            :protocol,              label: 'Protocol ID Field',      initial_value: RubySMB::SMB2::SMB2_TRANSFORM_PROTOCOL_ID
        string           :signature,             label: 'Signature', length: 16
        string           :nonce,                 label: 'Nonce',     length: 16
        uint32           :original_message_size, label: 'Original Message Size'
        uint16           :reserved0
        uint16           :flags,                 label: 'Flags / Encryption Algorithm'
        uint64           :session_id,            label: 'Session ID'
        array            :encrypted_data,        label: 'Encrypted Data', type: :uint8, read_until: :eof

        def decrypt(key, algorithm: 'AES-128-GCM')
          auth_data = self.to_binary_s[20...52]
          encrypted_data = self.encrypted_data.to_ary.pack('C*')

          case algorithm
          when 'AES-128-CCM'
            cipher = OpenSSL::CCM.new('AES', key, 16)
            unencrypted_data = cipher.decrypt(encrypted_data + self.signature, self.nonce[0...11], auth_data)
            unless unencrypted_data.length > 0
              raise OpenSSL::Cipher::CipherError  # raised for consistency with GCM mode
            end
          when 'AES-128-GCM'
            cipher = OpenSSL::Cipher.new(algorithm).decrypt
            cipher.key = key
            cipher.iv = self.nonce[0...12]
            cipher.auth_data = auth_data
            cipher.auth_tag = self.signature
            unencrypted_data = cipher.update(encrypted_data)
            cipher.final # raises OpenSSL::Cipher::CipherError on signature failure
          else
            raise ArgumentError.new('Invalid algorithm, must be either AES-128-CCM or AES-128-GCM')
          end

          unencrypted_data[0...self.original_message_size]
        rescue Exception => e
          raise RubySMB::Error::EncryptionError, "Error while decrypting with '#{algorithm}' (#{e.class}: #{e})"
        end

        def encrypt(unencrypted_data, key, algorithm: 'AES-128-GCM')
          if unencrypted_data.is_a? BinData::Record
            unencrypted_data = unencrypted_data.to_binary_s
          end

          self.original_message_size.assign(unencrypted_data.length)

          case algorithm
          when 'AES-128-CCM'
            cipher = OpenSSL::CCM.new('AES', key, 16)
            random_iv = OpenSSL::Random.random_bytes(11)
            self.nonce.assign(random_iv)
            result = cipher.encrypt(unencrypted_data, random_iv, self.to_binary_s[20...52])
            encrypted_data = result[0...-16]
            auth_tag = result[-16..-1]
          when 'AES-128-GCM'
            cipher = OpenSSL::Cipher.new(algorithm).encrypt
            cipher.iv_len = 12
            cipher.key = key
            self.nonce.assign(cipher.random_iv)
            cipher.auth_data = self.to_binary_s[20...52]
            encrypted_data = cipher.update(unencrypted_data) + cipher.final
            auth_tag = cipher.auth_tag
          else
            raise ArgumentError.new('Invalid algorithm, must be either AES-128-CCM or AES-128-GCM')
          end

          self.encrypted_data.assign(encrypted_data.bytes)
          self.signature.assign(auth_tag)
          nil
        rescue Exception => e
          raise RubySMB::Error::EncryptionError, "Error while encrypting with '#{algorithm}' (#{e.class}: #{e})"
        end
      end
    end
  end
end
