require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # [2.2.1.2.1 DOMAIN_CONTROLLER_INFOW](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/9b85a7a4-8d34-4b9e-9500-bf8644ebfc06)
      class DomainControllerInfoW < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_wide_stringz_ptr :domain_controller_name
        ndr_wide_stringz_ptr :domain_controller_address
        ndr_uint32           :domain_controller_address_type
        uuid                 :domain_guid
        ndr_wide_stringz_ptr :domain_name
        ndr_wide_stringz_ptr :dns_forest_name
        ndr_uint32           :flags
        ndr_wide_stringz_ptr :dc_site_name
        ndr_wide_stringz_ptr :client_site_name
      end

      class DomainControllerInfoWPtr < DomainControllerInfoW
        extend Ndr::PointerClassPlugin
      end
    end
  end
end
