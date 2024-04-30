module RubySMB
  module Dcerpc
    module Winreg

      # This class represents a GetKeySecurity Request Packet as defined in
      # [3.1.5.13 BaseRegGetKeySecurity (Opnum 12)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/b0e1868c-f4fd-4b43-959f-c0f0cac3ee26)
      class GetKeySecurityRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey                :hkey
        uint32                  :security_information
        rpc_security_descriptor :prpc_security_descriptor_in

        def initialize_instance
          super
          @opnum = REG_GET_KEY_SECURITY
        end
      end

    end
  end
end


