require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.2 RControlService (Opnum 1)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/e1c478be-117f-4512-9b67-17c20a48af97)
      class ControlServiceResponse < BinData::Record
        attr_reader :opnum

        endian :little

        service_status :lp_service_status
        ndr_uint32     :error_status

        def initialize_instance
          super
          @opnum = CONTROL_SERVICE
        end
      end

    end
  end
end


