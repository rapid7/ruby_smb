module RubySMB
  module Dcerpc
    module EncryptingFileSystem

      # [3.1.4.2.7 Receiving an EfsRpcQueryUsersOnFile Message (Opnum 6)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/a058dc6c-bb7e-491c-9143-a5cb1f7e7cea)
      class EfsRpcQueryUsersOnFileRequest < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_conf_var_wide_stringz :file_name

        def initialize_instance
          super
          @opnum = EFS_RPC_QUERY_USERS_ON_FILE
        end
      end
    end
  end
end
