module RubySMB
  module Dcerpc
    module Svcctl

      class SvcctlHandleW < Ndr::NdrWideStringzPtr; end

      # [3.1.4.15 ROpenSCManagerW (Opnum 15)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/dc84adb3-d51d-48eb-820d-ba1c6ca5faf2)
      class OpenSCManagerWRequest < BinData::Record
        attr_reader :opnum

        endian :little

        svcctl_handle_w      :lp_machine_name
        ndr_wide_stringz_ptr :lp_database_name
        ndr_uint32           :dw_desired_access

        def initialize_instance
          super
          @opnum = OPEN_SC_MANAGER_W
        end
      end

    end
  end
end
