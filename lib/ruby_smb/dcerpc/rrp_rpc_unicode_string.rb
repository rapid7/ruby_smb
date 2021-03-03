module RubySMB
  module Dcerpc

    # A RRP_UNICODE_STRING structure as defined in
    # [2.2.4 RRP_UNICODE_STRING](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/c0c90f11-a4c4-496a-ac09-8a8a3697ceef)
    class RrpUnicodeString < BinData::Primitive
      endian :little

      uint16          :buffer_length
      uint16          :maximum_length
      wide_string_ptr :buffer

      def get
        self.buffer
      end

      def set(buf)
        self.buffer = buf
        #self.buffer_length = self.buffer == :null ? 0 : self.buffer.referent.actual_count * 2
        self.buffer_length = self.buffer == :null ? 0 : (self.buffer.actual_count - 1) * 2
        # Don't reset maximum_length if the buffer is NULL to make sure we can
        # set it independently of the buffer size
        return if self.maximum_length > 0 && self.buffer == :null
        #self.maximum_length = self.buffer.referent.max_count * 2
        self.maximum_length = (self.buffer.max_count - 1) * 2
      end
    end

    # A pointer to a RRP_UNICODE_STRING structure
    class PrrpUnicodeString < RrpUnicodeString
      extend Ndr::PointerClassPlugin
      def initialize_shared_instance
        super
        extend Ndr::PointerPlugin
      end
    end

    # A RPC_UNICODE_STRING structure as defined in
    # [2.3.10 RPC_UNICODE_STRING](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/94a16bb6-c610-4cb9-8db6-26f15f560061)
    class RpcUnicodeString < BinData::Primitive
      # Same as RrpUnicodeString, but not necessary null terminated
      # TODO: check if #buffer should be substituted by a ConfVarArray of WideChar. Since WideStringPtr is always null terminated, this can be an issue if the string is not.
    end

    # A pointer to a RPC_UNICODE_STRING structure
    class PrpcUnicodeString < RpcUnicodeString
      extend Ndr::PointerClassPlugin
      def initialize_shared_instance
        super
        extend Ndr::PointerPlugin
      end
    end
  end
end

