module RubySMB
  module Dcerpc
    module PrintSystem

      # [3.1.4.4.4 RpcGetPrinterDriverDirectory (Opnum 12)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/9df11cf4-4098-4852-ad72-d1f75a82bffe)
      class RpcGetPrinterDriverDirectoryRequest < BinData::Record
        attr_reader :opnum

        endian :little

        def initialize_instance
          super
          @opnum = RPC_GET_PRINTER_DRIVER_DIRECTORY
        end

        ndr_wide_stringz_ptr :p_name
        ndr_wide_stringz_ptr :p_environment
        ndr_uint32           :level
        rprn_byte_array_ptr  :p_driver_directory
        ndr_uint32           :cb_buf
      end
    end
  end
end
