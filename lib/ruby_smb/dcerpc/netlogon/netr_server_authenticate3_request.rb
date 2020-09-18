require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # [3.5.4.4.2 NetrServerAuthenticate3 (Opnum 26)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/3a9ed16f-8014-45ae-80af-c0ecb06e2db9)
      class NetrServerAuthenticate3Request < BinData::Record
        attr_reader :opnum

        endian :little

        logonsrv_handle              :primary_name
        ndr_string                   :account_name
        netlogon_secure_channel_type :secure_channel_type
        ndr_string                   :computer_name
        netlogon_credential          :client_credential
        uint32                       :flags

        def initialize_instance
          super
          @opnum = NETR_SERVER_AUTHENTICATE3
        end

      end
    end
  end
end
