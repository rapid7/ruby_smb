module RubySMB
  module Dcerpc
    module Winreg

      # This class represents a BaseRegEnumValue Response Packet as defined in
      # [3.1.5.11 BaseRegEnumValue (Opnum 10)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/56e99ef3-05dc-4f24-bcf5-9cff00412945)
      class EnumValueResponse < BinData::Record
        attr_reader :opnum

        endian :little

        rrp_unicode_string :lp_value_name
        string             :pad, length: -> { pad_length }
        ndr_lp_dword       :lp_type
        ndr_lp_byte        :lp_data
        ndr_lp_dword       :lpcb_data
        ndr_lp_dword       :lpcb_len
        uint32             :error_status

        def initialize_instance
          super
          @opnum = REG_ENUM_VALUE
        end

        # Determines the correct length for the padding in front of
        # #lp_type. It should always force a 4-byte alignment.
        def pad_length
          offset = (lp_value_name.abs_offset + lp_value_name.to_binary_s.length) % 4
          (4 - offset) % 4
        end
      end

    end
  end
end

