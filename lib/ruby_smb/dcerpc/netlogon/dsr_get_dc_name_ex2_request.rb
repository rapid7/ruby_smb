require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # [3.5.4.3.1 DsrGetDcNameEx2 (Opnum 34)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/fb8e1146-a045-4c31-98d1-c68507ad5620)
      class DsrGetDcNameEx2Request < BinData::Record
        attr_reader :opnum

        endian :little

        logonsrv_handle       :computer_name
        ndr_wide_stringz_ptr  :account_name
        ndr_uint32            :allowable_account_control_bits
        ndr_wide_stringz_ptr  :domain_name
        uuid_ptr              :domain_guid
        ndr_wide_stringz_ptr  :site_name
        ndr_uint32            :flags

        def initialize_instance
          super
          @opnum = DSR_GET_DC_NAME_EX2
        end
      end
    end
  end
end
