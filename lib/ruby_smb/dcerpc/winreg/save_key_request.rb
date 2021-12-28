module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegSaveKey Request Packet as defined in
      # [3.1.5.20 BaseRegSaveKey (Opnum 20)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/f022247d-6ef1-4f46-b195-7f60654f4a0d)
      class SaveKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey                 :hkey
        rrp_unicode_string       :lp_file
        prpc_security_attributes :lp_security_attributes

        def initialize_instance
          super
          @opnum = REG_SAVE_KEY
        end
      end
    end
  end
end



