module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegEnumValue Request Packet as defined in
      # [3.1.5.11 BaseRegEnumValue (Opnum 10)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/56e99ef3-05dc-4f24-bcf5-9cff00412945)
      class EnumValueRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey           :hkey
        ndr_uint32         :dw_index
        rrp_unicode_string :lp_value_name
        #string             :pad, length: -> { pad_length }
        ndr_uint32_ptr     :lp_type
        ndr_byte_array_ptr :lp_data
        ndr_uint32_ptr     :lpcb_data
        ndr_uint32_ptr     :lpcb_len

        def initialize_instance
          super
          @opnum = REG_ENUM_VALUE
        end
      end
    end
  end
end

