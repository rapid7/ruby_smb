module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.12 RCreateServiceW (Opnum 12)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6a8ca926-9477-4dd4-b766-692fab07227e)
      class CreateServiceWResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32_ptr :lp_dw_tag_id
        sc_rpc_handle  :lp_sc_handle
        ndr_uint32     :error_status

        def initialize_instance
          super
          @opnum = CREATE_SERVICE_W
        end

      end

    end
  end
end
