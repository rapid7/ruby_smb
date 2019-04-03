module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegQueryValue Request Packet as defined in
      # [3.1.5.17 BaseRegQueryValue (Opnum 17)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/8bc10aa3-2f91-44e8-aa33-b3263c49ab9d)
      class QueryValueRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey           :hkey
        rrp_unicode_string :lp_value_name
        string             :pad, length: -> { pad_length }
        ndr_lp_dword       :lp_type
        ndr_lp_byte        :lp_data
        ndr_lp_dword       :lpcb_data
        ndr_lp_dword       :lpcb_len

        def initialize_instance
          super
          @opnum = REG_QUERY_VALUE
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


