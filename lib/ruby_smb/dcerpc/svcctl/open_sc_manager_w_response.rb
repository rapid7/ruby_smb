module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.15 ROpenSCManagerW (Opnum 15)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/dc84adb3-d51d-48eb-820d-ba1c6ca5faf2)
      class OpenSCManagerWResponse < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle :lp_sc_handle
        uint32        :error_status

        def initialize_instance
          super
          @opnum = OPEN_SC_MANAGER_W
        end

      end

    end
  end
end
