require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      class LpBoundedDword8k < BinData::Uint32le; end

      # [2.2.15 QUERY_SERVICE_CONFIGW](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/97200665-5631-42ea-9917-6f9b41f02391)
      class QueryServiceConfigW < RubySMB::Dcerpc::Ndr::NdrStruct
        endian :little

        uint32          :dw_service_type
        uint32          :dw_start_type
        uint32          :dw_error_control
        wide_string_ptr :lp_binary_path_name
        wide_string_ptr :lp_load_order_group
        uint32          :dw_tag_id
        wide_string_ptr :lp_dependencies
        wide_string_ptr :lp_service_start_name
        wide_string_ptr :lp_display_name

      end

      # [3.1.4.17 RQueryServiceConfigW (Opnum 17)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/89e2d5b1-19cf-44ca-969f-38eea9fe7f3c)
      class QueryServiceConfigWResponse < BinData::Record
        attr_reader :opnum

        endian :little

        query_service_config_w :lp_service_config
        lp_bounded_dword8k     :pcb_bytes_needed
        uint32                 :error_status

        def initialize_instance
          super
          @opnum = QUERY_SERVICE_CONFIG_W
        end
      end

    end
  end
end

