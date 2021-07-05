module RubySMB
  module Dcerpc
    module Winreg

      # This class represents a BaseRegEnumValue Response Packet as defined in
      # [3.1.5.11 BaseRegEnumValue (Opnum 10)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/56e99ef3-05dc-4f24-bcf5-9cff00412945)
      class EnumValueResponse < BinData::Record
        attr_reader :opnum

        endian :little

        rrp_unicode_string :lp_value_name
        ndr_uint32_ptr     :lp_type
        ndr_byte_array_ptr :lp_data
        ndr_uint32_ptr     :lpcb_data
        ndr_uint32_ptr     :lpcb_len
        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = REG_ENUM_VALUE
        end
      end
    end
  end
end

