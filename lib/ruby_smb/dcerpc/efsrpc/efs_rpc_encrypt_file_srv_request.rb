module RubySMB
  module Dcerpc
    module Efsrpc

      # [3.1.4.2.5 EfsRpcEncryptFileSrv (Opnum 4)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/0d599976-758c-4dbd-ac8c-c9db2a922d76)
      class EfsRpcEncryptFileSrvRequest < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_conf_var_wide_stringz :file_name

        def initialize_instance
          super
          @opnum = EFS_RPC_ENCRYPT_FILE_SRV
        end
      end
    end
  end
end
