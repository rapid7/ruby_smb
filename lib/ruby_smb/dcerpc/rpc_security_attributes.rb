module RubySMB
  module Dcerpc

    # This class represents a RPC_SECURITY_DESCRIPTOR structure as defined in
    # [2.2.8 RPC_SECURITY_DESCRIPTOR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/9729e781-8eb9-441b-82ca-e898f98d29c2)
    class RpcSecurityDescriptor < BinData::Record
      endian :little

      ndr_lp_byte_array :lp_security_descriptor
      uint32            :cb_in_security_descriptor
      uint32            :cb_out_security_descriptor
    end

    # This class represents a RPC_SECURITY_ATTRIBUTES structure as defined in
    # [2.2.7 RPC_SECURITY_ATTRIBUTES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/bc37b8cf-8c94-4804-ad53-0aaf5eaf0ecb)
    class RpcSecurityAttributes < BinData::Record
      endian :little

      uint32                  :n_length
      rpc_security_descriptor :rpc_security_descriptor
      uint8                   :b_inheritHandle
    end

    # This class represents a pointer to a RPC_SECURITY_ATTRIBUTES structure as defined in
    # [2.2.7 RPC_SECURITY_ATTRIBUTES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/bc37b8cf-8c94-4804-ad53-0aaf5eaf0ecb)
    class PrpcSecurityAttributes < Ndr::NdrPointer
      endian :little

      rpc_security_attributes :referent, onlyif: -> { self.referent_id != 0 }

      def do_read(io)
        super(io)
        if process_referent?
          self.referent.do_read(io) unless self.referent_id == 0
        end
      end

      def do_write(io)
        super(io)
        if process_referent?
          self.referent.do_write(io) unless self.referent_id == 0
        end
      end

      def set(v)
        if v == :null
          self.referent.clear
        else
          self.referent = v
        end
        super(v)
      end

      def get
        if self.referent_id == 0
          :null
        else
          self.referent
        end
      end
    end

  end
end

