module RubySMB
  module SMB2
    module Packet
      # An SMB2 TRANSFORM_HEADER Packet as defined in
      # [2.2.41 SMB2 TRANSFORM_HEADER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d6ce2327-a4c9-4793-be66-7b5bad2175fa)
      class TransformHeader < BinData::Record
        endian :little
        hide   :reserved0

        endian           :little
        bit32            :protocol,              label: 'Protocol ID Field',      initial_value: 0xFD534D42
        string           :signature,             label: 'Signature', length: 16
        string           :nonce,                 label: 'Nonce',     length: 16
        uint32           :original_message_size, label: 'Original Message Size'
        uint16           :reserved0
        uint16           :flags,                 label: 'Flags / Encryption Algorithm'
        uint64           :session_id,            label: 'Session ID'
        array            :encrypted_data,        label: 'Encrypted Data', type: :uint8, read_until: :eof

        def decrypt(key, algorithm: 'AES-128-GCM')
          cipher = build_cipher(:decrypt, algorithm, key)
          cipher.iv = self.nonce[0...cipher.iv_len]

          cipher.ccm_data_len = self.encrypted_data.size if algorithm == 'AES-128-CCM'
          cipher.auth_data = self.to_binary_s[20...52]

          cipher.auth_tag = self.signature

          cipher.update(self.encrypted_data.to_ary.pack('C*'))[0...self.original_message_size]
        end

        def encrypt(unencrypted_data, key, algorithm: 'AES-128-GCM')
          if unencrypted_data.is_a? BinData::Record
            unencrypted_data = unencrypted_data.to_binary_s
          end

          cipher = build_cipher(:encrypt, algorithm, key)
          self.nonce.assign(cipher.random_iv)

          self.original_message_size.assign(unencrypted_data.length)

          cipher.ccm_data_len = unencrypted_data.length if algorithm == 'AES-128-CCM'

          cipher.auth_data = self.to_binary_s[20...52]
          enc_data = cipher.update(unencrypted_data) + cipher.final
          self.encrypted_data.assign(enc_data.bytes)

          self.signature.assign(cipher.auth_tag)

          nil
        end

        private

        def build_cipher(mode, algorithm, key)
          unless ['AES-128-CCM', 'AES-128-GCM'].include?(algorithm)
            # Only GCM is supported right now due to a bug in the Ruby OpenSSL implementation that
            # prevents setting the data length.
            # see: https://github.com/ruby/openssl/pull/359
            raise ArgumentError.new('Invalid algorithm, must be either AES-128-CCM or AES-128-GCM')
          end

          cipher = OpenSSL::Cipher.new(algorithm)
          cipher.send(mode)

          case algorithm
          when 'AES-128-CCM'
            cipher.auth_tag_len = 16
            cipher.iv_len = 11
          when 'AES-128-GCM'
            cipher.iv_len = 12
          end
          cipher.key = key

          cipher
        end
      end
    end
  end
end
