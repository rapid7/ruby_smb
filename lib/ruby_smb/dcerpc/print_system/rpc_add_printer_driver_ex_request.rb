module RubySMB
  module Dcerpc
    module PrintSystem

      # [3.1.4.4.8 RpcAddPrinterDriverEx (Opnum 89)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b)
      class RpcAddPrinterDriverExRequest < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_wide_stringz_ptr :p_name
        driver_container     :p_driver_container
        ndr_uint32           :dw_file_copy_flags

        def initialize_instance
          super
          @opnum = RPC_ADD_PRINTER_DRIVER_EX
        end
      end
    end
  end
end
