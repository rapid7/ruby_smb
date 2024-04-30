module RubySMB
  module Dcerpc
    module Winreg

      # This class represents a SetKeySecurity Request Packet as defined in
      # [3.1.5.21 BaseRegSetKeySecurity (Opnum 21)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/da18856c-8a6d-4217-8e93-3625865e562c)
      class SetKeySecurityRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey                :hkey
        uint32                  :security_information
        rpc_security_descriptor :prpc_security_descriptor

        def initialize_instance
          super
          @opnum = REG_SET_KEY_SECURITY
        end
      end

    end
  end
end


