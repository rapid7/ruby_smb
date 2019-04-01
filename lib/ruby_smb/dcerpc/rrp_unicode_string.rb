require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc

    # A RRP_UNICODE_STRING structure as defined in
    # [2.2.4 RRP_UNICODE_STRING](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/c0c90f11-a4c4-496a-ac09-8a8a3697ceef)
    class RrpUnicodeString < BinData::Primitive
      endian :little

      uint16     :buffer_length,  initial_value: -> { buffer.to_s == "\0" ? 0 : buffer.actual_count * 2 }
      uint16     :maximum_length, initial_value: -> { buffer.to_s == "\0" ? 0 : buffer.max_count * 2 }
      ndr_lp_str :buffer

      def get
        self.buffer
      end

      def set(buf)
        self.buffer = buf
        self.buffer_length = self.buffer.to_s == "\0" ? 0 : self.buffer.actual_count * 2
        self.maximum_length = self.buffer.to_s == "\0" ? 0 : self.buffer.max_count * 2
      end
    end

    # A pointer to a RRP_UNICODE_STRING structure
    class PrrpUnicodeString < Ndr::NdrTopLevelFullPointer
      endian :little

      rrp_unicode_string :referent, onlyif: -> { !is_a_null_pointer? }
    end

  end
end

