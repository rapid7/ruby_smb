module RubySMB
  module Dcerpc
    module Winreg

      # This class represents a PREGISTRY_SERVER_NAME structure as defined in
      # [2.2.2 PREGISTRY_SERVER_NAME](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/8bcd15fd-1aa5-44e2-8662-112ec3e9817b)
      class PRegistryServerName < BinData::Array
        default_parameter type: :ndr_wide_char, referent_byte_align: 2
        extend Ndr::PointerClassPlugin
      end

      # This class is a generic class that represents OpenXXX Request packet,
      # used to open one of the root keys, as defined in:
      # [3.1.5.1 OpenClassesRoot (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/956a3052-6580-43ee-91aa-aaf61726149b)
      # [3.1.5.2 OpenCurrentUser (Opnum 1)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/ec140ed9-4d00-4c03-a15c-c7245a497ed5)
      # [3.1.5.3 OpenLocalMachine (Opnum 2)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/6cef29ae-21ba-423f-9158-05145ac80a5b)
      # [3.1.5.4 OpenPerformanceData (Opnum 3)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/7b514c63-6cad-4fe1-9780-743959e377e6)
      # [3.1.5.5 OpenUsers (Opnum 4)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/694e57f4-da3e-4285-8b71-3181d71d6cd1)
      # [3.1.5.25 OpenCurrentConfig (Opnum 27)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/160767d7-83cf-4718-a4f3-d864faee3bb1)
      # [3.1.5.28 OpenPerformanceText (Opnum 32)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/44954f6d-ef2c-4ec1-a27d-32b9b87e3c8a)
      # [3.1.5.29 OpenPerformanceNlsText (Opnum 33)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/3626fa8a-b20f-4243-bf85-cdb615ed2ca0)
      # The structure is define by the value of the #opnum parameter
      # e.g. (OpenLocalMachine):
      #   OpenRootKeyRequest.new(opnum: RubySMB::Dcerpc::Winreg::OPEN_HKLM)
      class OpenRootKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little
        p_registry_server_name :server_name
        regsam                 :sam_desired

        def initialize_instance
          super
          @opnum = get_parameter(:opnum) if has_parameter?(:opnum)
          self.server_name = :null
          self.sam_desired.maximum = 1 unless [OPEN_HKPD, OPEN_HKPT, OPEN_HKPN].include?(@opnum)
        end
      end

    end
  end
end
