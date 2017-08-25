module RubySMB
  module SMB1

    # An SMB1 connected remote Tree, as returned by a
    # [RubySMB::SMB1::Packet::TreeConnectRequest]
    class Tree

      # The client this Tree is connected through
      # @!attribute [rw] client
      #   @return [RubySMB::Client]
      attr_accessor :client

      # The current Guest Share Permissions
      # @!attribute [rw] guest_permissions
      #   @return [RubySMB::SMB1::BitField::DirectoryAccessMask]
      attr_accessor :guest_permissions

      # The current Maximal Share Permissions
      # @!attribute [rw] permissions
      #   @return [RubySMB::SMB1::BitField::DirectoryAccessMask]
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
        @id                 = response.smb_header.tid
        @guest_permissions  = response.parameter_block.guest_access_rights
        @permissions        = response.parameter_block.access_rights
      end

      # Disconnects this Tree from the current session
      #
      # @return [WindowsError::ErrorCode] the NTStatus sent back by the server.
      def disconnect!
        request = RubySMB::SMB1::Packet::TreeDisconnectRequest.new
        request.smb_header.tid = self.id
        raw_response = self.client.send_recv(request)
        response = RubySMB::SMB1::Packet::TreeDisconnectResponse.read(raw_response)
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
      def list(directory: '\\', pattern: '*', type: RubySMB::Fscc::FileInformation::FileFullDirectoryInformation )
        find_first_request = RubySMB::SMB1::Packet::Trans2::FindFirst2Request.new
        find_first_request.smb_header.tid         = self.id
        find_first_request.smb_header.flags2.eas  = 1

        search_path = directory.dup
        search_path << '\\' unless search_path.end_with?('\\')
        search_path << pattern
        search_path = '\\' + search_path unless search_path.start_with?('\\')

        # Set the search parameters
        t2_params = find_first_request.data_block.trans2_parameters
        t2_params.search_attributes.hidden    = 1
        t2_params.search_attributes.system    = 1
        t2_params.search_attributes.directory = 1
        t2_params.flags.close_eos             = 1
        t2_params.flags.resume_keys           = 1
        t2_params.information_level           = type::SMB1_FLAG
        t2_params.filename                    = search_path
        t2_params.search_count                = 100

        find_first_request.parameter_block.data_count             = 0
        find_first_request.parameter_block.data_offset            = 0
        find_first_request.parameter_block.total_parameter_count  = find_first_request.parameter_block.parameter_count
        find_first_request.parameter_block.max_parameter_count    = find_first_request.parameter_block.parameter_count
        find_first_request.parameter_block.max_data_count         = 16384

        raw_response  = self.client.send_recv(find_first_request)
        response      = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.read(raw_response)

      end

    end
  end
end