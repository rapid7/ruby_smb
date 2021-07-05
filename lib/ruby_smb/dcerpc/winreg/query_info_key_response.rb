module RubySMB
  module Dcerpc
    module Winreg
      # This class represents a BaseRegQueryInfoKey Response Packet as defined in
      # [3.1.5.16 BaseRegQueryInfoKey (Opnum 16)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/a886ba66-5c7b-4331-bacd-7c77edc95d85)
      class QueryInfoKeyResponse < BinData::Record
        attr_reader :opnum

        endian :little

        rrp_unicode_string :lp_class, initial_value: 0
        ndr_uint32         :lpc_sub_keys
        ndr_uint32         :lpc_max_sub_key_len
        ndr_uint32         :lpc_max_class_len
        ndr_uint32         :lpc_values
        ndr_uint32         :lpcb_max_value_name_len
        ndr_uint32         :lpcb_max_value_len
        ndr_uint32         :lpcb_security_descriptor
        ndr_file_time      :lpft_last_write_time
        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = REG_QUERY_INFO_KEY
        end
      end
    end
  end
end


