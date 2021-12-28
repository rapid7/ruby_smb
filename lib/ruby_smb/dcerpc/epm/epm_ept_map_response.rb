module RubySMB
  module Dcerpc
    module Epm

      # [2.2.1.2.5 ept_map Method](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab744583-430e-4055-8901-3c6bc007e791)
      class EpmEptMapResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_context_handle :entry_handle
        ndr_uint32         :num_towers
        ndr_conf_var_array :towers, type: :epm_twrpt
        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = EPT_MAP
        end
      end

    end
  end
end

