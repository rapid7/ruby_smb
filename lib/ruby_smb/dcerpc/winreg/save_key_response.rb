module RubySMB
  module Dcerpc
    module Winreg

      # This class represents a BaseRegSaveKey Response Packet as defined in
      # [3.1.5.20 BaseRegSaveKey (Opnum 20)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/f022247d-6ef1-4f46-b195-7f60654f4a0d)
      class SaveKeyResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32 :error_status

        def initialize_instance
          super
          @opnum = REG_CREATE_KEY
        end
      end

    end
  end
end

