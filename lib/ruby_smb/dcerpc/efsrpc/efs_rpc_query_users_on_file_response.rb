module RubySMB
  module Dcerpc
    module Efsrpc

      # [3.1.4.2.7 Receiving an EfsRpcQueryUsersOnFile Message (Opnum 6)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/a058dc6c-bb7e-491c-9143-a5cb1f7e7cea)
      class EfsRpcQueryUsersOnFileResponse < BinData::Record
        attr_reader :opnum

        endian :little

        encryption_certificate_hash_list_ptr :users
        ndr_uint32                           :error_status

        def initialize_instance
          super
          @opnum = EFS_RPC_QUERY_USERS_ON_FILE
        end
      end
    end
  end
end
