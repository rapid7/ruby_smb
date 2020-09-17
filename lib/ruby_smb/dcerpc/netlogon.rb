module RubySMB
  module Dcerpc
    module Netlogon

      # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/592edbc8-f6f1-40c0-9ab3-fe6725ac6d7e
      UUID = '12345678-1234-abcd-ef00-01234567cffb'
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      NETR_SERVER_REQ_CHALLENGE = 4
      NETR_SERVER_AUTHENTICATE3 = 26
      NETR_SERVER_PASSWORD_SET2 = 30

      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/d55e2632-7163-4f6c-b662-4b870e8cc1cd
      class NetlogonCredential < BinData::Uint8Array
        default_parameters initial_length: 8
      end

      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/76c93227-942a-4687-ab9d-9d972ffabdab
      class NetlogonAuthenticator < BinData::Record
        endian :little

        netlogon_credential :credential
        uint32              :timestamp
      end

      require 'ruby_smb/dcerpc/netlogon/netr_server_req_challenge_request'
      require 'ruby_smb/dcerpc/netlogon/netr_server_req_challenge_response'
      require 'ruby_smb/dcerpc/netlogon/netr_server_authenticate3_request'
      require 'ruby_smb/dcerpc/netlogon/netr_server_authenticate3_response'

      # Calculate the netlogon session key from the provided share secret and
      # challenges. The share secret is an NTLM hash.
      #
      # @param shared_secret [String] the share secret between the client and the server
      # @param client_challenge [String] the client challenge portion of the negotiation
      # @param server_challenge [String] the server challenge portion of the negotiation
      # @return [String] the session key for encryption
      def self.calculate_session_key(shared_secret, client_challenge, server_challenge)
        hmac = OpenSSL::HMAC.new(shared_secret, OpenSSL::Digest::SHA256.new)
        hmac << client_challenge
        hmac << server_challenge
        hmac.digest.first(16)
      end

    end
  end
end
