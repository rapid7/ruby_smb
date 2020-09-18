require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # [3.5.4.4.5 NetrServerPasswordSet2 (Opnum 30)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/14b020a8-0bcf-4af5-ab72-cc92bc6b1d81)
      class NetrServerPasswordSet2Request < BinData::Record
        attr_reader :opnum

        endian :little

        logonsrv_handle              :primary_name
        ndr_string                   :account_name
        netlogon_secure_channel_type :secure_channel_type
        ndr_string                   :computer_name
        netlogon_authenticator       :authenticator
        ndr_fixed_byte_array         :clear_new_password, length: 516 # this is an encrypted NL_TRUST_PASSWORD

        def initialize_instance
          super
          @opnum = Netlogon::NETR_SERVER_PASSWORD_SET2
        end
      end
    end
  end
end
