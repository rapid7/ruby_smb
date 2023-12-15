module RubySMB
  module Dcerpc
    module Efsrpc

      # [3.1.4.2.6 Receiving an EfsRpcDecryptFileSrv Message (Opnum 5)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/043715de-caee-402a-a61b-921743337e78)
      class EfsRpcDecryptFileSrvResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = EFS_RPC_DECRYPT_FILE_SRV
        end
      end

    end
  end
end
