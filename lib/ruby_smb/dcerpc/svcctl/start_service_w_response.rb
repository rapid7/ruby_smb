require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.19 RStartServiceW (Opnum 19)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d9be95a2-cf01-4bdc-b30f-6fe4b37ada16)
      class StartServiceWResponse < BinData::Record
        attr_reader :opnum

        endian :little

        uint32 :error_status

        def initialize_instance
          super
          @opnum = START_SERVICE_W
        end
      end
    end
  end
end



