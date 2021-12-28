module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.16 ROpenServiceW (Opnum 16)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6d0a4225-451b-4132-894d-7cef7aecfd2d)
      class OpenServiceWRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle             :lp_sc_handle
        ndr_conf_var_wide_stringz :lp_service_name
        ndr_uint32                :dw_desired_access

        def initialize_instance
          super
          @opnum = OPEN_SERVICE_W
        end
      end

    end
  end
end
