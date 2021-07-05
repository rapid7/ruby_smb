module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegEnumKey Request Packet as defined in
      # [3.1.5.10 BaseRegEnumKey (Opnum 9)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/668627e9-e0eb-4ab1-911f-0af589beeac3)
      class EnumKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey            :hkey
        ndr_uint32          :dw_index
        rrp_unicode_string  :lp_name
        prrp_unicode_string :lp_class
        ndr_file_time_ptr   :lpft_last_write_time

        def initialize_instance
          super
          @opnum = REG_ENUM_KEY
        end
      end
    end
  end
end

