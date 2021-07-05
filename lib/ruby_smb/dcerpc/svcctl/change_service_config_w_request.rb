require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.11 RChangeServiceConfigW (Opnum 11)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/61ea7ed0-c49d-4152-a164-b4830f16c8a4)
      class ChangeServiceConfigWRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle       :h_service
        ndr_uint32          :dw_service_type
        ndr_uint32          :dw_start_type
        ndr_uint32          :dw_error_control
        ndr_wide_string_ptr :lp_binary_path_name
        ndr_wide_string_ptr :lp_load_order_group
        ndr_uint32_ptr      :dw_tag_id
        ndr_conf_array      :lp_dependencies, type: :ndr_uint8
        ndr_uint32          :dw_depend_size, value: -> { self.lp_dependencies.size }
        ndr_wide_string_ptr :lp_service_start_name
        ndr_conf_array      :lp_password, type: :ndr_uint8
        ndr_uint32          :dw_pw_size, value: -> { self.lp_password.size }
        ndr_wide_string_ptr :lp_display_name

        def initialize_instance
          super
          @opnum = CHANGE_SERVICE_CONFIG_W
        end
      end

    end
  end
end

