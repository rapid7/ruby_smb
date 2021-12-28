module RubySMB
  module Dcerpc
    module Drsr

      # [4.1.3 IDL_DRSBind (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/605b1ea1-9cdc-428f-ab7a-70120e020a3d)
      class DrsBindResponse < BinData::Record
        attr_reader :opnum

        endian :little

        drs_extensions_ptr :ppext_server
        drs_handle         :ph_drs
        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = DRS_BIND
        end
      end

    end
  end
end



