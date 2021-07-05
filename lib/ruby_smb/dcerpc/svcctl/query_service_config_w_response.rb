require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      class LpBoundedDword8k < RubySMB::Dcerpc::Ndr::NdrUint32; end

      # [2.2.15 QUERY_SERVICE_CONFIGW](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/97200665-5631-42ea-9917-6f9b41f02391)
      class QueryServiceConfigW < RubySMB::Dcerpc::Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32          :dw_service_type
        ndr_uint32          :dw_start_type
        ndr_uint32          :dw_error_control
        ndr_wide_string_ptr :lp_binary_path_name
        ndr_wide_string_ptr :lp_load_order_group
        ndr_uint32          :dw_tag_id
        ndr_wide_string_ptr :lp_dependencies
        ndr_wide_string_ptr :lp_service_start_name
        ndr_wide_string_ptr :lp_display_name

      end

      # [3.1.4.17 RQueryServiceConfigW (Opnum 17)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/89e2d5b1-19cf-44ca-969f-38eea9fe7f3c)
      class QueryServiceConfigWResponse < BinData::Record
        attr_reader :opnum

        endian :little

        query_service_config_w :lp_service_config
        lp_bounded_dword8k     :pcb_bytes_needed
        ndr_uint32             :error_status

        def initialize_instance
          super
          @opnum = QUERY_SERVICE_CONFIG_W
        end
      end

    end
  end
end

