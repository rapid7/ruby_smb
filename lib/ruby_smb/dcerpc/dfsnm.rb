module RubySMB
  module Dcerpc
    module Dfsnm

      UUID = '4fc742e0-4a10-11cf-8273-00aa004ae673'
      VER_MAJOR = 3
      VER_MINOR = 0

      # Operation numbers
      NETR_DFS_ADD_STD_ROOT    = 0x000c
      NETR_DFS_REMOVE_STD_ROOT = 0x000d

      require 'ruby_smb/dcerpc/dfsnm/netr_dfs_add_std_root_request'
      require 'ruby_smb/dcerpc/dfsnm/netr_dfs_add_std_root_response'
      require 'ruby_smb/dcerpc/dfsnm/netr_dfs_remove_std_root_request'
      require 'ruby_smb/dcerpc/dfsnm/netr_dfs_remove_std_root_response'

      def netr_dfs_add_std_root(server_name, root_share, comment: '', api_flags: 0)
        netr_dfs_add_std_root_request = NetrDfsAddStdRootRequest.new(
          server_name: server_name,
          root_share: root_share,
          comment: comment,
          api_flags: api_flags
        )
        response = dcerpc_request(netr_dfs_add_std_root_request)
        begin
          netr_dfs_add_std_root_response = NetrDfsAddStdRootResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading NetrDfsAddStdRootResponse'
        end
        unless netr_dfs_add_std_root_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::DfsnmError.new(
            "Error returned with netr_dfs_add_std_root: "\
            "#{WindowsError::Win32.find_by_retval(netr_dfs_add_std_root_response.error_status.value).join(',')}",
            error_status: netr_dfs_add_std_root_response.error_status.value
          )
        end

        nil
      end

      def netr_dfs_remove_std_root(server_name, root_share, api_flags: 0)
        netr_dfs_remove_std_root_request = NetrDfsRemoveStdRootRequest.new(
          server_name: server_name,
          root_share: root_share,
          api_flags: api_flags
        )
        response = dcerpc_request(netr_dfs_remove_std_root_request)
        begin
          netr_dfs_remove_std_root_response = NetrDfsRemoveStdRootResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading NetrDfsRemoveStdRootResponse'
        end
        unless netr_dfs_remove_std_root_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::DfsnmError.new(
            "Error returned with netr_dfs_remove_std_root: "\
            "#{WindowsError::Win32.find_by_retval(netr_dfs_remove_std_root_response.error_status.value).join(',')}",
            error_status: netr_dfs_remove_std_root_response.error_status.value
          )
        end

        nil
      end

    end
  end
end
