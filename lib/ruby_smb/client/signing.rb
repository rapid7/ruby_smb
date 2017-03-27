module RubySMB
  class Client

    # Contains the methods for handling packet signing
    module Signing

      # The NTLM Session Key used for signing
      # @!attribute [rw] session_key
      #   @return [String]
      attr_accessor :session_key

      def smb1_sign

      end

      def smb2_sign(packet)
        if self.signing_required && !self.session_key.empty?
          hmac = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, self.session_key, packet.to_binary_s)
          packet.smb2_header.signature = hmac
          packet
        else
          packet
        end
      end

    end
  end
end