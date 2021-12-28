module RubySMB
  module Dcerpc
    module Drsr

      # [4.1.25 IDL_DRSUnbind (Opnum 1)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/49eb17c9-b6a9-4cea-bef8-66abda8a7850)
      class DrsUnbindRequest < BinData::Record
        attr_reader :opnum

        endian :little

        drs_handle :ph_drs

        def initialize_instance
          super
          @opnum = DRS_UNBIND
        end
      end

    end
  end
end



