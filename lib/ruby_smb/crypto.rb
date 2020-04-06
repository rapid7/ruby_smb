module RubySMB
  module Crypto
    module KDF
      def self.counter_mode(ki, label, context, length: 128)
        digest = OpenSSL::Digest.new('SHA256')
        r = 32

        n = length / 256
        n = 1 if n == 0

        raise ArgumentError if n > 2**r - 1
        result = ""

        n.times do |i|
          input = [i + 1].pack('L>')
          input << label
          input << "\x00"
          input << context
          input << [length].pack('L>')
          k = OpenSSL::HMAC.digest(digest, ki, input)
          result << k
        end

        return result[0...(length / 8)]
      rescue OpenSSL::OpenSSLError => e
        raise RubySMB::Error::EncryptionError, "Crypto::KDF.counter_mode OpenSSL error: #{e.message}"
      end
    end
  end
end
