module RubySMB
  module Dcerpc
    module Drsr

      # [4.1.3 IDL_DRSBind (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/605b1ea1-9cdc-428f-ab7a-70120e020a3d)
      class DrsBindRequest < BinData::Record
        attr_reader :opnum

        endian :little

        uuid_ptr           :puuid_client_dsa, initial_value: NTSAPI_CLIENT_GUID
        drs_extensions_ptr :pext_client

        def initialize_instance
          super
          @opnum = DRS_BIND
        end
      end

    end
  end
end


