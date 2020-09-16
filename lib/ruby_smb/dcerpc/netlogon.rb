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

      class NetlogonCredential < BinData::Uint8Array
        default_parameters length: 8
      end

      require 'ruby_smb/dcerpc/netlogon/netr_server_req_challenge_request'
      require 'ruby_smb/dcerpc/netlogon/netr_server_authenticate3_request'

    end
  end
end
