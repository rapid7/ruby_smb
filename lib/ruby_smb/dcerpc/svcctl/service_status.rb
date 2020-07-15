require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      # [2.2.47 SERVICE_STATUS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/4e91ff36-ab5f-49ed-a43d-a308e72b0b3c)
      class ServiceStatus < BinData::Record
        endian :little

        uint32 :dw_service_type
        uint32 :dw_current_state
        uint32 :dw_controls_accepted
        uint32 :dw_win32_exit_code
        uint32 :dw_service_specific_exit_code
        uint32 :dw_check_point
        uint32 :dw_wait_hint
      end

    end
  end
end



