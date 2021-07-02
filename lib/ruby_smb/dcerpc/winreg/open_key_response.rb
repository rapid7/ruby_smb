module RubySMB
  module Dcerpc
    module Winreg

      class PrpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegOpenKey Response Packet as defined in
      # [3.1.5.15 BaseRegOpenKey (Opnum 15)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/8cb48f55-19e1-4ea2-8d76-dd0f6934f0d9)
      class OpenKeyResponse < BinData::Record
        attr_reader :opnum

        endian :little

        prpc_hkey     :phk_result
        ndr_uint32    :error_status

        def initialize_instance
          super
          @opnum = REG_OPEN_KEY
        end
      end

    end
  end
end

