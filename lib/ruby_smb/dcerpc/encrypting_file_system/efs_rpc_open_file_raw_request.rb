module RubySMB
  module Dcerpc
    module EncryptingFileSystem

      # [3.1.4.2.1 EfsRpcOpenFileRaw (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8)
      class EfsRpcOpenFileRawRequest < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_conf_var_wide_stringz :file_name
        ndr_uint32                :flags

        def initialize_instance
          super
          @opnum = EFS_RPC_OPEN_FILE_RAW
        end
      end
    end
  end
end
