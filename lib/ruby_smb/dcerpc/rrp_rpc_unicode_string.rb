module RubySMB
  module Dcerpc

    # A RRP_UNICODE_STRING structure as defined in
    # [2.2.4 RRP_UNICODE_STRING](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/c0c90f11-a4c4-496a-ac09-8a8a3697ceef)
    class RrpUnicodeString < Ndr::NdrStruct
      default_parameters byte_align: 4
      endian :little

      ndr_uint16           :buffer_length
      ndr_uint16           :maximum_length
      ndr_wide_stringz_ptr :buffer

      def assign(val)
        case val
        when :null
          self.buffer = val
          self.buffer_length = 0
          self.maximum_length = 0
        when BinData::Stringz, BinData::String, String
          self.buffer = val.to_s
          val_length = val.strip.length
          val_length += 1 unless val == ''
          self.buffer_length = val_length * 2
          self.maximum_length = val_length * 2
        else
          super
        end
      end

      def set_maximum_length(val)
        if self.buffer
          self.buffer.max_count = val / 2
        end
        self.maximum_length.assign(val)
      end

      def to_s
        self.buffer
      end
    end

    # A pointer to a RRP_UNICODE_STRING structure
    class PrrpUnicodeString < RrpUnicodeString
      extend Ndr::PointerClassPlugin
    end

    # A RPC_UNICODE_STRING structure as defined in
    # [2.3.10 RPC_UNICODE_STRING](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/94a16bb6-c610-4cb9-8db6-26f15f560061)
    class RpcUnicodeString < Ndr::NdrStruct
      # Same as RrpUnicodeString, but not necessary null terminated
      #
      # It is the caller responsability to null terminate the string, if it has
      # to. This structure won't do it automatically the way RrpUnicodeString
      # do.
      #
      # It also takes care of detecting the terminating null character and
      # exclude when calculating buffer_length and maximum_length.
      default_parameters byte_align: 4
      endian :little

      ndr_uint16          :buffer_length
      ndr_uint16          :maximum_length
      ndr_wide_string_ptr :buffer

      def assign(val)
        case val
        when :null
          self.buffer = val
          self.buffer_length = 0
          self.maximum_length = 0
        when BinData::Stringz, BinData::String, String
          self.buffer = val.to_s
          val_length = val.strip.length
          self.buffer_length = val_length * 2
          self.maximum_length = val_length * 2
        else
          super
        end
      end

      def set_maximum_length(val)
        if self.buffer
          self.buffer.max_count = val / 2
        end
        self.maximum_length.assign(val)
      end

      def to_s
        self.buffer
      end
    end

    # A pointer to a RPC_UNICODE_STRING structure
    class PrpcUnicodeString < RpcUnicodeString
      extend Ndr::PointerClassPlugin
    end
  end
end

