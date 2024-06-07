require 'ruby_smb/dcerpc/ndr'
require 'ruby_smb/dcerpc/netlogon/domain_controller_infow'

module RubySMB
  module Dcerpc
    module Netlogon

      # [3.5.4.3.1 DsrGetDCNameEx2 (Opnum 34)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/fb8e1146-a045-4c31-98d1-c68507ad5620)
      class DsrGetDCNameEx2Response < BinData::Record
        attr_reader :opnum

        endian :little

        domain_controller_info_w_ptr :domain_controller_info
        ndr_uint32                   :error_status

        def initialize_instance
          super
          @opnum = DSR_GET_DC_NAME_EX2
        end
      end
    end
  end
end
