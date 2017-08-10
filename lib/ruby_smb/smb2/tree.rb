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
        request = set_header_fields(request)
        raw_response = self.client.send_recv(request)
        response = RubySMB::SMB2::Packet::TreeDisconnectResponse.read(raw_response)
        response.status_code
      end

      # List `directory` on the remote share.
      #
      # @example
      #   tree = client.tree_connect("\\\\192.168.99.134\\Share")
      #   tree.list(directory: "path\\to\\directory")
      #
      # @param directory [String] path to the directory to be listed
      # @param pattern [String] search pattern
      # @param type [Class] file information class
      # @return [Array] array of directory structures
      def list(directory: nil, pattern: '*', type: RubySMB::Fscc::FileInformation::FileIdFullDirectoryInformation )
        create_request = RubySMB::SMB2::Packet::CreateRequest.new
        create_request = set_header_fields(create_request)

        create_request.impersonation_level            = RubySMB::ImpersonationLevels::SEC_IMPERSONATE
        create_request.create_options.directory_file  = 1
        create_request.file_attributes.directory      = 1
        create_request.desired_access.list            = 1
        create_request.share_access.read_access       = 1
        create_request.create_disposition             = RubySMB::Dispositions::FILE_OPEN



        if directory.nil? || directory.empty?
          create_request.name   = "\x00"
          create_request.length = 0
        else
          create_request.name = directory
        end

        raw_response = self.client.send_recv(create_request)
        create_response = RubySMB::SMB2::Packet::CreateResponse.read(raw_response)

      end


      def set_header_fields(request)
        request.smb2_header.tree_id = self.id
        request.smb2_header.credit_charge = 1
        request.smb2_header.credits = 256
        request
      end

    end
  end
end