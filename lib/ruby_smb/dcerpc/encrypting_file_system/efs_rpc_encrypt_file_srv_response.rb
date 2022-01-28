module RubySMB
  module Dcerpc
    module EncryptingFileSystem

      # [3.1.4.2.5 EfsRpcEncryptFileSrv (Opnum 4)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/0d599976-758c-4dbd-ac8c-c9db2a922d76)
      class EfsRpcEncryptFileSrvResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = EFS_RPC_ENCRYPT_FILE_SRV
        end
      end
    end
  end
end
