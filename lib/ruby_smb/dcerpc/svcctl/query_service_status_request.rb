module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.7 RQueryServiceStatus (Opnum 6)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/cf94d915-b4e1-40e5-872b-a9cb3ad09b46)
      class QueryServiceStatusRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle :h_service

        def initialize_instance
          super
          @opnum = QUERY_SERVICE_STATUS
        end
      end

    end
  end
end


