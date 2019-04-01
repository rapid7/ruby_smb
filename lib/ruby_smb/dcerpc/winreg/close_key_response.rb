module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegCloseKey Response Packet as defined in
      # [3.1.5.6 BaseRegCloseKey (Opnum 5)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/bc7545ff-0a54-4465-a95a-396b5c2995df)
      class CloseKeyResponse < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey  :hkey
        uint32    :error_status

        def initialize_instance
          super
          @opnum = REG_CLOSE_KEY
        end
      end

    end
  end
end


