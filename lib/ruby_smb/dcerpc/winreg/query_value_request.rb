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
        ndr_uint32_ptr     :lp_type
        ndr_byte_array_ptr :lp_data
        ndr_uint32_ptr     :lpcb_data
        ndr_uint32_ptr     :lpcb_len

        def initialize_instance
          super
          @opnum = REG_QUERY_VALUE
        end
      end
    end
  end
end


