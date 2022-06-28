module RubySMB
  module Dcerpc
    module Dfsnm

      # [3.1.4.4.2 NetrDfsRemoveStdRoot (Opnum 13)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/e9da023d-554a-49bc-837a-69f22d59fd18)
      class NetrDfsRemoveStdRootRequest < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_wide_string_ptr :server_name
        ndr_wide_string_ptr :root_share
        ndr_uint32          :api_flags

        def initialize_instance
          super
          @opnum = NETR_DFS_REMOVE_STD_ROOT
        end
      end

    end
  end
end
