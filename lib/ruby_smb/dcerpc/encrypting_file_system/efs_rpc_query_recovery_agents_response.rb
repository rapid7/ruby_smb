module RubySMB
  module Dcerpc
    module EncryptingFileSystem

      # [3.1.4.2.8 Receiving an EfsRpcQueryRecoveryAgents Message (Opnum 7)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/cf759c00-1b90-4c33-9ace-f51c20149cea)
      class EfsRpcQueryRecoveryAgentsResponse < BinData::Record
        attr_reader :opnum

        endian :little

        encryption_certificate_hash_list_ptr :recover_agents
        ndr_uint32                           :error_status

        def initialize_instance
          super
          @opnum = EFS_RPC_QUERY_RECOVERY_AGENTS
        end
      end
    end
  end
end
