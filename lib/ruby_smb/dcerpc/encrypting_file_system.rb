module RubySMB
  module Dcerpc
    module EncryptingFileSystem
      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/403c7ae0-1a3a-4e96-8efc-54e79a2cc451
      UUID = EFSRPC_UUID = 'df1941c5-fe89-4e79-bf10-463657acf44d'.freeze
      LSARPC_UUID = 'c681d488-d850-11d0-8c52-00c04fd90f7e'.freeze
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      EFS_RPC_OPEN_FILE_RAW = 0
      EFS_RPC_WRITE_FILE_RAW = 1
      EFS_RPC_CLOSE_RAW = 3
      EFS_RPC_ENCRYPT_FILE_SRV = 4
      EFS_RPC_DECRYPT_FILE_SRV = 5
      EFS_RPC_QUERY_USERS_ON_FILE = 6
      EFS_RPC_QUERY_RECOVERY_AGENTS = 7
      EFS_RPC_REMOVE_USERS_FROM_FILE = 8
      EFS_RPC_ADD_USERS_TO_FILE = 9
      EFS_RPC_NOT_SUPPORTED = 11
      EFS_RPC_FILE_KEY_INFO = 12
      EFS_RPC_DUPLICATE_ENCRYPTION_INFO_FILE = 13
      EFS_RPC_ADD_USERS_TO_FILE_EX = 15
      EFS_RPC_FILE_KEY_INFO_EX = 16
      EFS_RPC_GET_ENCRYPTED_FILE_METADATA = 18
      EFS_RPC_SET_ENCRYPTED_FILE_METADATA = 19
      EFS_RPC_FLUSH_EFS_CACHE = 20
      EFS_RPC_ENCRYPT_FILE_EX_SRV = 21
      EFS_RPC_QUERY_PROTECTORS = 22

      # EfsRpcOpenFileRaw flags,
      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8
      CREATE_FOR_IMPORT = 0x00000001
      CREATE_FOR_DIR = 0x00000002
      OVERWRITE_HIDDEN = 0x00000004
      EFS_DROP_ALTERNATE_STREAMS = 0x00000010

      # [2.2.7 EFS_HASH_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/242d857f-ac8e-4cc8-b5e4-9314a942f45e)
      class EfsHashBlob < Ndr::NdrStruct
        endian :little
        default_parameter byte_align: 4

        ndr_uint32   :cb_data
        ndr_byte_conf_array_ptr :b_data
      end

      class EfsHashBlobPtr < EfsHashBlob
        extend Ndr::PointerClassPlugin
      end

      # [2.2.10 ENCRYPTION_CERTIFICATE_HASH](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/3a7e7151-edcb-4b32-a119-35cdce1584c0)
      class EncryptionCertificateHash < Ndr::NdrStruct
        endian :little
        default_parameter byte_align: 4

        ndr_uint32                :cb_total_length
        prpc_sid                  :user_sid
        efs_hash_blob_ptr         :certificate_hash
        ndr_wide_stringz_ptr      :lp_display_information
      end

      class EncryptionCertificateHashPtr < EncryptionCertificateHash
        extend Ndr::PointerClassPlugin
      end

      class EncryptionCertificateHashPtrArrayPtr < Ndr::NdrConfArray
        default_parameter type: :encryption_certificate_hash_ptr
        extend Ndr::PointerClassPlugin
      end

      # [2.2.11 ENCRYPTION_CERTIFICATE_HASH_LIST](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/2718804c-6ab9-45fd-98cf-541bc3b6bc75)
      class EncryptionCertificateHashList < BinData::Record
        endian :little
        default_parameter byte_align: 4

        uint32                                    :ncert_hash
        encryption_certificate_hash_ptr_array_ptr :users
      end

      class EncryptionCertificateHashListPtr < EncryptionCertificateHashList
        extend Ndr::PointerClassPlugin
      end

      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_decrypt_file_srv_request'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_decrypt_file_srv_response'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_encrypt_file_srv_request'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_encrypt_file_srv_response'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_open_file_raw_request'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_open_file_raw_response'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_query_recovery_agents_request'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_query_recovery_agents_response'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_query_users_on_file_request'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_query_users_on_file_response'
    end
  end
end
