module RubySMB
  module Dcerpc
    module PrintSystem

      # [3.1.4.4.8 RpcAddPrinterDriverEx (Opnum 89)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b)
      class RpcAddPrinterDriverExResponse < BinData::Record
        attr_reader :opnum

        endian :little

        def initialize_instance
          super
          @opnum = RPC_ADD_PRINTER_DRIVER_EX
        end

        ndr_uint32 :error_status
      end
    end
  end
end
