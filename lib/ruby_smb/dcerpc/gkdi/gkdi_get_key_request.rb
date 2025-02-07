module RubySMB
  module Dcerpc
    module Gkdi

      # [3.1.4.1 GetKey (Opnum 0)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39)
      class GkdiGetKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32     :cb_target_sd
        ndr_conf_array :pb_target_sd, type: :ndr_uint8
        uuid_ptr       :p_root_key_id
        ndr_int32      :l0_key_id
        ndr_int32      :l1_key_id
        ndr_int32      :l2_key_id

        def initialize_instance
          super
          @opnum = GKDI_GET_KEY
        end
      end

    end
  end
end
