module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.12 RCreateServiceW (Opnum 12)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6a8ca926-9477-4dd4-b766-692fab07227e)
      class CreateServiceWRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle             :h_sc_object
        ndr_conf_var_wide_stringz :lp_service_name
        ndr_wide_stringz_ptr      :lp_display_name
        ndr_uint32                :dw_desired_access
        ndr_uint32                :dw_service_type
        ndr_uint32                :dw_start_type
        ndr_uint32                :dw_error_control
        ndr_conf_var_wide_stringz :lp_binary_path_name
        ndr_wide_stringz_ptr      :lp_load_order_group
        ndr_uint32_ptr            :lp_dw_tag_id
        svcctl_byte_array_ptr     :lp_dependencies, type: :ndr_uint8
        ndr_uint32                :dw_depend_size, initial_value: -> { lp_dependencies.size }
        ndr_wide_stringz_ptr      :lp_service_start_name
        svcctl_byte_array_ptr     :lp_password, type: :ndr_uint8
        ndr_uint32                :dw_pw_size, initial_value: -> { lp_password.size }

        def initialize_instance
          super
          @opnum = CREATE_SERVICE_W
        end
      end

    end
  end
end
