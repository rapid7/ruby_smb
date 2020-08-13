require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.11 RChangeServiceConfigW (Opnum 11)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/61ea7ed0-c49d-4152-a164-b4830f16c8a4)
      class ChangeServiceConfigWResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_lp_dword :dw_tag_id
        uint32       :error_status

        def initialize_instance
          super
          @opnum = CHANGE_SERVICE_CONFIG_W
        end
      end

    end
  end
end


