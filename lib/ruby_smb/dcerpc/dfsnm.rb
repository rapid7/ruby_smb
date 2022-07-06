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

      # Create a new stand-alone DFS namespace.
      #
      # @param server_name [String] The host name of the DFS root target.
      # @param root_share [String] The DFS root target share name.
      # @param comment [String] A comment associated with the DFS namespace.
      # @return nothing is returned on success
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   NetrDfsAddStdRootResponse packet
      # @raise [RubySMB::Dcerpc::Error::DfsnmError] if the response error status
      #   is not ERROR_SUCCESS
      def netr_dfs_add_std_root(server_name, root_share, comment: '')
        netr_dfs_add_std_root_request = NetrDfsAddStdRootRequest.new(
          server_name: server_name,
          root_share: root_share,
          comment: comment
        )
        response = dcerpc_request(netr_dfs_add_std_root_request)
        begin
          netr_dfs_add_std_root_response = NetrDfsAddStdRootResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading NetrDfsAddStdRootResponse'
        end
        unless netr_dfs_add_std_root_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          status_code = WindowsError::Win32.find_by_retval(netr_dfs_add_std_root_response.error_status.value).first
          raise RubySMB::Dcerpc::Error::DfsnmError.new(
            "Error returned with netr_dfs_add_std_root: #{status_code}",
            status_code: status_code
          )
        end

        nil
      end

      # Delete the specified stand-alone DFS namespace.
      #
      # @param server_name [String] The host name of the DFS root target.
      # @param root_share [String] The DFS root target share name.
      # @return nothing is returned on success
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   NetrDfsRemoveStdRootResponse packet
      # @raise [RubySMB::Dcerpc::Error::DfsnmError] if the response error status
      #   is not ERROR_SUCCESS
      def netr_dfs_remove_std_root(server_name, root_share)
        netr_dfs_remove_std_root_request = NetrDfsRemoveStdRootRequest.new(
          server_name: server_name,
          root_share: root_share
        )
        response = dcerpc_request(netr_dfs_remove_std_root_request)
        begin
          netr_dfs_remove_std_root_response = NetrDfsRemoveStdRootResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading NetrDfsRemoveStdRootResponse'
        end
        unless netr_dfs_remove_std_root_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          status_code = WindowsError::Win32.find_by_retval(netr_dfs_remove_std_root_response.error_status.value).first
          raise RubySMB::Dcerpc::Error::DfsnmError.new(
            "Error returned with netr_dfs_remove_std_root: #{status_code}",
            status_code: status_code
          )
        end

        nil
      end

    end
  end
end
