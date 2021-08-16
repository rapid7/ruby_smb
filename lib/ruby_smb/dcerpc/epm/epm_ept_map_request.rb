module RubySMB
  module Dcerpc
    module Epm

      # [2.2.1.2.5 ept_map Method](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab744583-430e-4055-8901-3c6bc007e791)
      # [https://pubs.opengroup.org/onlinepubs/9629399/apdxo.htm](https://pubs.opengroup.org/onlinepubs/9629399/apdxo.htm)
      class EpmEptMapRequest < BinData::Record
        attr_reader :opnum

        endian :little

        uuid_ptr           :obj
        epm_twrpt          :map_tower
        ndr_context_handle :entry_handle
        ndr_uint32         :max_towers

        def initialize_instance
          super
          @opnum = EPT_MAP
        end
      end

    end
  end
end

