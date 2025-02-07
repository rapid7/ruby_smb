module RubySMB
  module Dcerpc
    module Gkdi

      # [3.1.4.1 GetKey (Opnum 0)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39)
      class GkdiGetKeyResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32              :pcb_out
        ndr_byte_conf_array_ptr :pbb_out
        ndr_uint32              :error_status

        def initialize_instance
          super
          @opnum = GKDI_GET_KEY
        end
      end

    end
  end
end
