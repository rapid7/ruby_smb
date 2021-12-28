require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      # [2.2.47 SERVICE_STATUS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/4e91ff36-ab5f-49ed-a43d-a308e72b0b3c)
      class ServiceStatus < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :dw_service_type
        ndr_uint32 :dw_current_state
        ndr_uint32 :dw_controls_accepted
        ndr_uint32 :dw_win32_exit_code
        ndr_uint32 :dw_service_specific_exit_code
        ndr_uint32 :dw_check_point
        ndr_uint32 :dw_wait_hint
      end

    end
  end
end



