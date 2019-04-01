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
        uint32              :dw_index
        rrp_unicode_string  :lp_name
        string              :pad1,     length: -> { pad_length1 }
        prrp_unicode_string :lp_class, initial_value: 0
        string              :pad2,     length: -> { pad_length2 }
        ndr_lp_file_time    :lpft_last_write_time

        def initialize_instance
          super
          @opnum = REG_ENUM_KEY
        end

        # Determines the correct length for the padding in front of
        # #lp_class. It should always force a 4-byte alignment.
        def pad_length1
          offset = (lp_name.abs_offset + lp_name.to_binary_s.length) % 4
          (4 - offset) % 4
        end

        # Determines the correct length for the padding in front of
        # #lpft_last_write_time. It should always force a 4-byte alignment.
        def pad_length2
          offset = (lp_class.abs_offset + lp_class.to_binary_s.length) % 4
          (4 - offset) % 4
        end
      end

    end
  end
end

