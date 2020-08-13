require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc

    # A RRP_UNICODE_STRING structure as defined in
    # [2.2.4 RRP_UNICODE_STRING](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/c0c90f11-a4c4-496a-ac09-8a8a3697ceef)
    class RrpUnicodeString < BinData::Primitive
      endian :little

      uint16     :buffer_length
      uint16     :maximum_length
      ndr_lp_str :buffer

      def get
        self.buffer
      end

      def set(buf)
        self.buffer = buf
        self.buffer_length = self.buffer == :null ? 0 : self.buffer.referent.actual_count * 2
        # Don't reset maximum_length if the buffer is NULL to make sure we can
        # set it independently of the buffer size
        return if self.maximum_length > 0 && self.buffer == :null
        self.maximum_length = self.buffer.referent.max_count * 2
      end
    end

    # A pointer to a RRP_UNICODE_STRING structure
    class PrrpUnicodeString < Ndr::NdrPointer
      endian :little

      rrp_unicode_string :referent, onlyif: -> { self.referent_id != 0 }
    end

  end
end

