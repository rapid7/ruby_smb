require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # [3.5.4.4.2 NetrServerAuthenticate3 (Opnum 26)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/3a9ed16f-8014-45ae-80af-c0ecb06e2db9)
      class NetrServerAuthenticate3Response < BinData::Record
        attr_reader :opnum

        endian :little

        netlogon_credential :server_credential
        ndr_uint32          :negotiate_flags
        ndr_uint32          :account_rid
        ndr_uint32          :error_status

        def initialize_instance
          super
          @opnum = NETR_SERVER_AUTHENTICATE3
        end

      end
    end
  end
end
