module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegCloseKey Request Packet as defined in
      # [3.1.5.6 BaseRegCloseKey (Opnum 5)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/bc7545ff-0a54-4465-a95a-396b5c2995df)
      class CloseKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey  :hkey

        def initialize_instance
          super
          @opnum = REG_CLOSE_KEY
        end
      end

    end
  end
end
