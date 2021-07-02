module RubySMB
  module Dcerpc
    module Winreg

      # This class represents a BaseRegEnumKey Response Packet as defined in
      # [3.1.5.10 BaseRegEnumKey (Opnum 9)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/668627e9-e0eb-4ab1-911f-0af589beeac3)
      class EnumKeyResponse < BinData::Record
        attr_reader :opnum

        endian :little

        rrp_unicode_string  :lp_name
        #string              :pad1,     length: -> { pad_length1 }
        prrp_unicode_string :lp_class
        #string              :pad2,     length: -> { pad_length2 }
        ndr_file_time_ptr   :lpft_last_write_time
        ndr_uint32          :error_status

        def initialize_instance
          super
          @opnum = REG_ENUM_KEY
        end
      end
    end
  end
end

