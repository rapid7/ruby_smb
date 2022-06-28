module RubySMB
  module Dcerpc
    module Dfsnm

      # [3.1.4.4.2 NetrDfsRemoveStdRoot (Opnum 13)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/e9da023d-554a-49bc-837a-69f22d59fd18)
      class NetrDfsRemoveStdRootResponse< BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32 :error_status

        def initialize_instance
          super
          @opnum = NETR_DFS_REMOVE_STD_ROOT
        end
      end

    end
  end
end
