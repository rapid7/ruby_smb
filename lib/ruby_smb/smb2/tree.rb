module RubySMB
  module SMB2

    # An SMB2 connected remote Tree, as returned by a
    # [RubySMB::SMB2::Packet::TreeConnectRequest]
    class Tree

      # The client this Tree is connected through
      # @!attribute [rw] client
      #   @return [RubySMB::Client]
      attr_accessor :client

      # The current Maximal Share Permissions
      # @!attribute [rw] permissions
      #   @return [RubySMB::SMB2::BitField::DirectoryAccessMask]
      attr_accessor :permissions

      # The share path associated with this Tree
      # @!attribute [rw] share
      #   @return [String]
      attr_accessor :share

      # The Tree ID for this Tree
      # @!attribute [rw] id
      #   @return [Integer]
      attr_accessor :id

      def initialize(client:, share:, response:)
        @client             = client
        @share              = share
        @id                 = response.smb2_header.tree_id
        @permissions        = response.maximal_access
      end

      # Disconnects this Tree from the current session
      #
      # @return [WindowsError::ErrorCode] the NTStatus sent back by the server.
      def disconnect!
        request = RubySMB::SMB2::Packet::TreeDisconnectRequest.new
        request.smb2_header.tree_id = self.id
        raw_response = self.client.send_recv(request)
        response = RubySMB::SMB2::Packet::TreeDisconnectResponse.read(raw_response)
        response.status_code
      end


    end
  end
end