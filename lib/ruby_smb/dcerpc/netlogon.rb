module RubySMB
  module Dcerpc
    module Netlogon

      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/592edbc8-f6f1-40c0-9ab3-fe6725ac6d7e
      UUID = '12345678-1234-abcd-ef00-01234567cffb'
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      NETR_SERVER_REQ_CHALLENGE = 4
      NETR_SERVER_AUTHENTICATE3 = 26
      NETR_SERVER_PASSWORD_SET2 = 30
      DSR_GET_DC_NAME_EX2 = 34

      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/3b224201-b531-43e2-8c79-b61f6dea8640
      class LogonsrvHandle < Ndr::NdrWideStringzPtr; end

      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/d55e2632-7163-4f6c-b662-4b870e8cc1cd
      class NetlogonCredential < Ndr::NdrFixedByteArray
        default_parameters initial_length: 8
      end

      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/76c93227-942a-4687-ab9d-9d972ffabdab
      class NetlogonAuthenticator < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        netlogon_credential :credential
        ndr_uint32          :timestamp
      end

      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/4d1235e3-2c96-4e9f-a147-3cb338a0d09f
      class NetlogonSecureChannelType < Ndr::NdrEnum
        # enum example from dmendel/bindata#38 https://github.com/dmendel/bindata/issues/38#issuecomment-46397163
        ALL = {
          0 => :NullSecureChannel,
          1 => :MsvApSecureChannel,
          2 => :WorkstationSecureChannel,
          3 => :TrustedDnsDomainSecureChannel,
          4 => :TrustedDomainSecureChannel,
          5 => :UasServerSecureChannel,
          6 => :ServerSecureChannel,
          7 => :CdcServerSecureChannel
        }
        ALL.each_pair { |val,sym| const_set(sym.to_s.gsub(/([a-z])([A-Z])/, '\1_\2').upcase, val) }
        default_parameter assert: -> { ALL.keys.include? value }

        def as_enum
          ALL[value]
        end

        def assign(val)
          if val.is_a? Symbol
            val = ALL.key(val)
            raise ArgumentError, 'invalid value name' if val.nil?
          end

          super
        end
      end

      require 'ruby_smb/dcerpc/netlogon/netr_server_authenticate3_request'
      require 'ruby_smb/dcerpc/netlogon/netr_server_authenticate3_response'
      require 'ruby_smb/dcerpc/netlogon/netr_server_password_set2_request'
      require 'ruby_smb/dcerpc/netlogon/netr_server_password_set2_response'
      require 'ruby_smb/dcerpc/netlogon/netr_server_req_challenge_request'
      require 'ruby_smb/dcerpc/netlogon/netr_server_req_challenge_response'
      require 'ruby_smb/dcerpc/netlogon/dsr_get_dc_name_ex2_request'
      require 'ruby_smb/dcerpc/netlogon/dsr_get_dc_name_ex2_response'

      # Calculate the netlogon session key from the provided shared secret and
      # challenges. The shared secret is an NTLM hash.
      #
      # @param shared_secret [String] the share secret between the client and the server
      # @param client_challenge [String] the client challenge portion of the negotiation
      # @param server_challenge [String] the server challenge portion of the negotiation
      # @return [String] the session key for encryption
      def self.calculate_session_key(shared_secret, client_challenge, server_challenge)
        client_challenge = client_challenge.to_binary_s if client_challenge.is_a? NetlogonCredential
        server_challenge = server_challenge.to_binary_s if server_challenge.is_a? NetlogonCredential

        hmac = OpenSSL::HMAC.new(shared_secret, OpenSSL::Digest::SHA256.new)
        hmac << client_challenge
        hmac << server_challenge
        hmac.digest.first(16)
      end

      # Encrypt the input data using the specified session key. This is used for
      # certain Netlogon service operations including the authentication
      # process. Per the specification, this uses AES-128-CFB8 with an all zero
      # initialization vector.
      #
      # @param session_key [String] the session key to use for encryption (must be 16 bytes long)
      # @param input_data [String] the data to encrypt
      # @return [String] the encrypted data
      def self.encrypt_credential(session_key, input_data)
        cipher = OpenSSL::Cipher.new('AES-128-CFB8').encrypt
        cipher.iv = "\x00" * 16
        cipher.key = session_key
        cipher.update(input_data) + cipher.final
      end
    end
  end
end
