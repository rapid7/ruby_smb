require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.11 RChangeServiceConfigW (Opnum 11)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/61ea7ed0-c49d-4152-a164-b4830f16c8a4)
      class ChangeServiceConfigWRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle       :h_service
        uint32              :dw_service_type
        uint32              :dw_start_type
        uint32              :dw_error_control
        ndr_wide_string_ptr :lp_binary_path_name
        string              :pad1, length: -> { pad_length(self.lp_binary_path_name) }
        ndr_wide_string_ptr :lp_load_order_group
        string              :pad2, length: -> { pad_length(self.lp_load_order_group) }
        ndr_uint32_ptr      :dw_tag_id
        ndr_conf_array      :lp_dependencies, type: :ndr_uint8
        string              :pad3, length: -> { pad_length(self.lp_dependencies) }
        uint32              :dw_depend_size, value: -> { self.lp_dependencies.size }
        ndr_wide_string_ptr :lp_service_start_name
        string              :pad4, length: -> { pad_length(self.lp_service_start_name) }
        ndr_conf_array      :lp_password, type: :ndr_uint8
        string              :pad5, length: -> { pad_length(self.lp_password) }
        uint32              :dw_pw_size, value: -> { self.lp_password.size }
        ndr_wide_string_ptr :lp_display_name

        def initialize_instance
          super
          @opnum = CHANGE_SERVICE_CONFIG_W
        end

        # Determines the correct length for the padding, so that the next
        # field is 4-byte aligned.
        def pad_length(prev_element)
          offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
          (4 - offset) % 4
        end
      end

    end
  end
end

