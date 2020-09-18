require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # [3.5.4.4.1 NetrServerReqChallenge (Opnum 4)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/5ad9db9f-7441-4ce5-8c7b-7b771e243d32)
      class NetrServerReqChallengeRequest < BinData::Record
        attr_reader :opnum

        endian :little

        logonsrv_handle     :primary_name
        ndr_string          :computer_name
        netlogon_credential :client_challenge

        def initialize_instance
          super
          @opnum = NETR_SERVER_REQ_CHALLENGE
        end

      end
    end
  end
end
