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

      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_decrypt_file_srv_request'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_decrypt_file_srv_response'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_encrypt_file_srv_request'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_encrypt_file_srv_response'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_open_file_raw_request'
      require 'ruby_smb/dcerpc/encrypting_file_system/efs_rpc_open_file_raw_response'
    end
  end
end
