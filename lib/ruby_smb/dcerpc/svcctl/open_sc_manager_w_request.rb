module RubySMB
  module Dcerpc
    module Svcctl

      class SvcctlHandleW < Ndr::NdrWideStringPtr; end

      # [3.1.4.15 ROpenSCManagerW (Opnum 15)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/dc84adb3-d51d-48eb-820d-ba1c6ca5faf2)
      class OpenSCManagerWRequest < BinData::Record
        attr_reader :opnum

        endian :little

        svcctl_handle_w     :lp_machine_name
        string              :pad1, length: -> { pad_length(self.lp_machine_name) }
        ndr_wide_string_ptr :lp_database_name
        string              :pad2, length: -> { pad_length(self.lp_database_name) }
        uint32              :dw_desired_access

        def initialize_instance
          super
          @opnum = OPEN_SC_MANAGER_W
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
