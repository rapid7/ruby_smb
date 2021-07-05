require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # [3.5.4.4.5 NetrServerPasswordSet2 (Opnum 30)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/14b020a8-0bcf-4af5-ab72-cc92bc6b1d81)
      class NetrServerPasswordSet2Response < BinData::Record
        attr_reader :opnum

        endian :little

        netlogon_authenticator :return_authenticator
        ndr_uint32             :error_status

        def initialize_instance
          super
          @opnum = Netlogon::NETR_SERVER_PASSWORD_SET2
        end
      end
    end
  end
end
