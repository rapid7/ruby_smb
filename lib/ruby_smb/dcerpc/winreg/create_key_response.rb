module RubySMB
  module Dcerpc
    module Winreg

      class PrpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegCreateKey Response Packet as defined in
      # [3.1.5.7 BaseRegCreateKey (Opnum 6)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/c7186ae2-1c82-45e9-933b-97d9873657e8)
      class CreateKeyResponse < BinData::Record
        # Create disposition
        # The key did not exist and was created.
        REG_CREATED_NEW_KEY     = 0x00000001
        # The key already existed and was opened without being changed.
        REG_OPENED_EXISTING_KEY = 0x00000002

        attr_reader :opnum

        endian :little

        prpc_hkey      :hkey
        ndr_uint32_ptr :lpdw_disposition
        uint32         :error_status

        def initialize_instance
          super
          @opnum = REG_CREATE_KEY
        end
      end

    end
  end
end




