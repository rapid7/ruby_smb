module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.17 RQueryServiceConfigW (Opnum 17)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/89e2d5b1-19cf-44ca-969f-38eea9fe7f3c)
      class QueryServiceConfigWRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle :h_service
        ndr_uint32    :cb_buf_size

        def initialize_instance
          super
          @opnum = QUERY_SERVICE_CONFIG_W
        end
      end

    end
  end
end



