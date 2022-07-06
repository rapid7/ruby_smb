module RubySMB
  module Dcerpc
    module Dfsnm

      # [3.1.4.4.1 NetrDfsAddStdRoot (Opnum 12)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/b18ef17a-7a9c-4e22-b1bf-6a4d07e87b2d)
      class NetrDfsAddStdRootResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32 :error_status

        def initialize_instance
          super
          @opnum = NETR_DFS_ADD_STD_ROOT
        end
      end

    end
  end
end
