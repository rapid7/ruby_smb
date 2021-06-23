module RubySMB
  module Dcerpc

    # This class represents a RPC_SECURITY_DESCRIPTOR structure as defined in
    # [2.2.8 RPC_SECURITY_DESCRIPTOR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/9729e781-8eb9-441b-82ca-e898f98d29c2)
    class RpcSecurityDescriptor < BinData::Record
      endian :little

      ndr_byte_array_ptr :lp_security_descriptor
      uint32             :cb_in_security_descriptor
      uint32             :cb_out_security_descriptor
    end

    # This class represents a RPC_SECURITY_ATTRIBUTES structure as defined in
    # [2.2.7 RPC_SECURITY_ATTRIBUTES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/bc37b8cf-8c94-4804-ad53-0aaf5eaf0ecb)
    class RpcSecurityAttributes < BinData::Record
      endian :little

      uint32                  :n_length
      rpc_security_descriptor :rpc_security_descriptor
      ndr_uint8               :b_inheritHandle
    end

    # This class represents a pointer to a RPC_SECURITY_ATTRIBUTES structure as defined in
    # [2.2.7 RPC_SECURITY_ATTRIBUTES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/bc37b8cf-8c94-4804-ad53-0aaf5eaf0ecb)
    class PrpcSecurityAttributes < RpcSecurityAttributes
      extend Ndr::PointerClassPlugin
      def initialize_shared_instance
        super
        extend Ndr::PointerPlugin
      end
    end

  end
end

