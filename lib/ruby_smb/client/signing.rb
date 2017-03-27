module RubySMB
  class Client

    # Contains the methods for handling packet signing
    module Signing

      # The NTLM Session Key used for signing
      # @!attribute [rw] session_key
      #   @return [String]
      attr_accessor :session_key

      def smb1_sign(packet)
        if self.signing_required && !self.session_key.empty?
          packet.smb_header.security_features = self.sequence_counter
          signature = OpenSSL::Digest::MD5.digest(self.session_key + packet.to_binary_s)[0,8]
          packet.smb_header.security_features = signature
          self.sequence_counter += 1
          packet
        else
          packet
        end
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