module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.12 RCreateServiceW (Opnum 12)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6a8ca926-9477-4dd4-b766-692fab07227e)
      class CreateServiceWRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle             :h_sc_object
        ndr_conf_var_wide_stringz :lp_service_name
        ndr_uint32                :lp_u_display_name, initial_value: -> { rand(0xfffffffe)+1 }
        ndr_conf_var_wide_stringz :lp_display_name, onlyif: -> { lp_u_display_name.nonzero? }
        ndr_uint32                :dw_desired_access
        ndr_uint32                :dw_service_type
        ndr_uint32                :dw_start_type
        ndr_uint32                :dw_error_control
        ndr_conf_var_wide_stringz :lp_binary_path_name
        ndr_uint32                :lp_u_load_order_group, initial_value: -> { rand(0xfffffffe)+1 }
        ndr_conf_var_wide_stringz :lp_load_order_group, onlyif: -> { lp_u_load_order_group.nonzero? }
        ndr_uint32                :lp_dw_tag_id
        ndr_byte_array_ptr        :lp_dependencies
        ndr_uint32                :dw_depend_size
        ndr_uint32                :lp_u_service_start_name, initial_value: -> { rand(0xfffffffe)+1 }
        ndr_conf_var_wide_stringz :lp_service_start_name, onlyif: -> { lp_u_service_start_name.nonzero? }
        ndr_byte_array_ptr        :lp_password
        ndr_uint32                :dw_pw_size

        def initialize_instance
          super
          @opnum = CREATE_SERVICE_W
        end
      end

    end
  end
end
