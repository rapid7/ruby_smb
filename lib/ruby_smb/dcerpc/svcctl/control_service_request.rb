require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.2 RControlService (Opnum 1)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/e1c478be-117f-4512-9b67-17c20a48af97)
      class ControlServiceRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle :h_service
        ndr_uint32    :dw_control

        def initialize_instance
          super
          @opnum = CONTROL_SERVICE
        end
      end

    end
  end
end


