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
        string             :pad1, length: -> { pad_length(self.lp_value_name) }
        ndr_lp_dword       :lp_type
        ndr_lp_byte_array  :lp_data
        string             :pad2, length: -> { pad_length(self.lp_data) }
        ndr_lp_dword       :lpcb_data
        ndr_lp_dword       :lpcb_len

        def initialize_instance
          super
          @opnum = REG_QUERY_VALUE
        end

        # Determines the correct length for the padding, so that the next
        # field is 4-byte aligned.
        def pad_length(prev_element)
          offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
          (4 - offset) % 4
        end
      end

    end
  end
end


