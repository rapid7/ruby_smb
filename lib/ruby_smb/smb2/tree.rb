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
        create_response = open_directory(directory:directory)
        file_id         = create_response.file_id

        directory_request                         = RubySMB::SMB2::Packet::QueryDirectoryRequest.new
        directory_request.file_information_class  = type::SMB2_FLAG
        directory_request.file_id                 = file_id
        directory_request.name                    = pattern
        directory_request.output_length           = 65535

        directory_request = set_header_fields(directory_request)

        files = []

        loop do
          response            = self.client.send_recv(directory_request)
          directory_response  = RubySMB::SMB2::Packet::QueryDirectoryResponse.read(response)

          status_code         = directory_response.smb2_header.nt_status.to_nt_status

          break if status_code == WindowsError::NTStatus::STATUS_NO_MORE_FILES

          unless status_code == WindowsError::NTStatus::STATUS_SUCCESS

            raise RubySMB::Error::UnexpectedStatusCode, status_code.to_s
          end

          files += directory_response.results(type)
          # Reset the message id so the client can update appropriately.
          directory_request.smb2_header.message_id = 0
        end

        files
      end

      # 'Opens' a directory file on the remote end, using a CreateRequest. This
      # can be used to open an existing directory, or create a new one, depending
      # on the disposition set.
      #
      # @param directory [String] the name of the directory file
      # @param disposition [Integer] the create disposition to use, should be one of {RubySMB::Dispositions}
      # @param impersonation [Integer] the impersonation level to use, should be one of {RubySMB::ImpersonationLevels}
      # @param read [Boolean] whether to request read access
      # @param write [Boolean] whether to request write access
      # @param delete [Boolean] whether to request delete access
      # @return [RubySMB::SMB2::Packet::CreateResponse] the response packet returned from the server
      def open_directory(directory:nil, disposition: RubySMB::Dispositions::FILE_OPEN,
                         impersonation: RubySMB::ImpersonationLevels::SEC_IMPERSONATE,
                         read:true, write: false, delete: false)

        create_request  = open_directory_packet(directory:directory, disposition:disposition,
                                                impersonation: impersonation, read:read, write:write,delete:delete)
        raw_response    = self.client.send_recv(create_request)
        RubySMB::SMB2::Packet::CreateResponse.read(raw_response)
      end

      # Creates the Packet for the #open_directory method.
      #
      # @param directory [String] the name of the directory file
      # @param disposition [Integer] the create disposition to use, should be one of {RubySMB::Dispositions}
      # @param impersonation [Integer] the impersonation level to use, should be one of {RubySMB::ImpersonationLevels}
      # @param read [Boolean] whether to request read access
      # @param write [Boolean] whether to request write access
      # @param delete [Boolean] whether to request delete access
      # @return [RubySMB::SMB2::Packet::CreateRequest] the request packet to send to the server
      def open_directory_packet(directory:nil, disposition: RubySMB::Dispositions::FILE_OPEN,
                                impersonation: RubySMB::ImpersonationLevels::SEC_IMPERSONATE,
                                read:true, write: false, delete: false)
        create_request = RubySMB::SMB2::Packet::CreateRequest.new
        create_request = set_header_fields(create_request)

        create_request.impersonation_level            = impersonation
        create_request.create_options.directory_file  = 1
        create_request.file_attributes.directory      = 1
        create_request.desired_access.list            = 1
        create_request.share_access.read_access       = 1 if read
        create_request.share_access.write_access      = 1 if write
        create_request.share_access.delete_access     = 1 if delete
        create_request.create_disposition             = disposition



        if directory.nil? || directory.empty?
          create_request.name   = "\x00"
          create_request.name_length = 0
        else
          create_request.name = directory
        end
        create_request
      end

      # Sets a few preset header fields that will always be set the same
      # way for Tree operations. This is, the TreeID, Credits, and Credit Charge.
      #
      # @param [RubySMB::SMB2::Packet] the request packet to modify
      # @return [RubySMB::SMB2::Packet] the modified packet.
      def set_header_fields(request)
        request.smb2_header.tree_id = self.id
        request.smb2_header.credit_charge = 1
        request.smb2_header.credits = 256
        request
      end

    end
  end
end