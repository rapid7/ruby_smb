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

      # Whether or not the share associated with this tree connect needs to be encrypted (SMB 3.x)
      # @!attribute [rw] tree_connect_encrypt_data
      #   @return [Boolean]
      attr_accessor :tree_connect_encrypt_data

      def initialize(client:, share:, response:, encrypt: false)
        @client              = client
        @share               = share
        @id                  = response.smb2_header.tree_id
        @permissions         = response.maximal_access
        @share_type          = response.share_type
        @tree_connect_encrypt_data = encrypt
      end

      # Disconnects this Tree from the current session
      #
      # @return [WindowsError::ErrorCode] the NTStatus sent back by the server.
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a TreeDisconnectResponse packet
      def disconnect!
        request = RubySMB::SMB2::Packet::TreeDisconnectRequest.new
        request = set_header_fields(request)
        raw_response = client.send_recv(request, encrypt: @tree_connect_encrypt_data)
        response = RubySMB::SMB2::Packet::TreeDisconnectResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::TreeDisconnectResponse::COMMAND,
            packet:         response
          )
        end
        response.status_code
      end

      def open_pipe(opts)
        # Make sure we don't modify the caller's hash options
        opts = opts.dup
        opts[:filename] = opts[:filename].dup
        opts[:filename] = opts[:filename][1..-1] if opts[:filename].start_with?('\\'.encode(opts[:filename].encoding))
        _open(**opts)
      end

      def open_file(opts)
        # Make sure we don't modify the caller's hash options
        opts = opts.dup
        opts[:filename] = opts[:filename].dup
        opts[:filename] = opts[:filename][1..-1] if opts[:filename].start_with?('\\'.encode(opts[:filename].encoding))
        _open(**opts)
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
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a QueryDirectoryResponse packet
      def list(directory: nil, pattern: '*', type: RubySMB::Fscc::FileInformation::FileIdFullDirectoryInformation)
        create_response = open_directory(directory: directory)
        opened_directory = RubySMB::SMB2::File.new(tree: self, response: create_response, name: directory)
        file_id         = create_response.file_id

        directory_request                         = RubySMB::SMB2::Packet::QueryDirectoryRequest.new
        directory_request.file_information_class  = type::CLASS_LEVEL
        directory_request.file_id                 = file_id
        directory_request.name                    = pattern

        max_read = client.server_max_read_size
        max_read = 65536 unless client.server_supports_multi_credit
        credit_charge = 0
        if client.server_supports_multi_credit
          credit_charge = (max_read - 1) / 65536 + 1
        end
        directory_request.output_length = max_read
        directory_request.smb2_header.credit_charge = credit_charge

        directory_request = set_header_fields(directory_request)

        files = []
        loop do
          response            = client.send_recv(directory_request, encrypt: @tree_connect_encrypt_data)
          directory_response  = RubySMB::SMB2::Packet::QueryDirectoryResponse.read(response)
          unless directory_response.valid?
            raise RubySMB::Error::InvalidPacket.new(
              expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
              expected_cmd:   RubySMB::SMB2::Packet::QueryDirectoryResponse::COMMAND,
              packet:         directory_response
            )
          end

          status_code         = directory_response.smb2_header.nt_status.to_nt_status

          break if status_code == WindowsError::NTStatus::STATUS_NO_MORE_FILES

          unless status_code == WindowsError::NTStatus::STATUS_SUCCESS
            raise RubySMB::Error::UnexpectedStatusCode, status_code
          end

          files += directory_response.results(type)
          # Reset the message id so the client can update appropriately.
          directory_request.smb2_header.message_id = 0
        end
        files
      ensure
        opened_directory.close if opened_directory
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
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a CreateResponse packet
      def open_directory(directory: nil, disposition: RubySMB::Dispositions::FILE_OPEN,
                         impersonation: RubySMB::ImpersonationLevels::SEC_IMPERSONATE,
                         read: true, write: false, delete: false, desired_delete: false)

        create_request  = open_directory_packet(directory: directory, disposition: disposition,
                                                impersonation: impersonation, read: read, write: write, delete: delete,
                                                desired_delete: desired_delete)
        raw_response    = client.send_recv(create_request, encrypt: @tree_connect_encrypt_data)
        response = RubySMB::SMB2::Packet::CreateResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::CreateResponse::COMMAND,
            packet:         response
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end

        response
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
      def open_directory_packet(directory: nil, disposition: RubySMB::Dispositions::FILE_OPEN,
                                impersonation: RubySMB::ImpersonationLevels::SEC_IMPERSONATE,
                                read: true, write: false, delete: false, desired_delete: false)
        create_request = RubySMB::SMB2::Packet::CreateRequest.new
        create_request = set_header_fields(create_request)

        create_request.impersonation_level            = impersonation
        create_request.create_options.directory_file  = 1
        create_request.file_attributes.directory      = 1
        create_request.desired_access.list            = 1
        create_request.share_access.read_access       = 1 if read
        create_request.share_access.write_access      = 1 if write
        create_request.share_access.delete_access     = 1 if delete
        create_request.desired_access.delete_access   = 1 if desired_delete
        create_request.create_disposition             = disposition

        if directory.nil? || directory.empty?
          create_request.name = "\x00"
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
        request.smb2_header.tree_id = id
        request.smb2_header.credits = 256
        request
      end

      private

      def _open(filename:, attributes: nil, options: nil, disposition: RubySMB::Dispositions::FILE_OPEN,
                    impersonation: RubySMB::ImpersonationLevels::SEC_IMPERSONATE, read: true, write: false, delete: false)

        create_request = RubySMB::SMB2::Packet::CreateRequest.new
        create_request = set_header_fields(create_request)

        # If the user supplied file attributes, use those, otherwise set some
        # sane defaults.
        if attributes
          create_request.file_attributes = attributes
        else
          create_request.file_attributes.directory  = 0
          create_request.file_attributes.normal     = 1
        end

        # If the user supplied Create Options, use those, otherwise set some
        # sane defaults.
        if options
          create_request.create_options = options
        else
          create_request.create_options.directory_file      = 0
          create_request.create_options.non_directory_file  = 1
        end

        if read
          create_request.share_access.read_access = 1
          create_request.desired_access.read_attr = 1
          create_request.desired_access.read_data = 1
        end

        if write
          create_request.share_access.write_access   = 1
          create_request.desired_access.write_data   = 1
          create_request.desired_access.append_data  = 1
        end

        if delete
          create_request.share_access.delete_access   = 1
          create_request.desired_access.delete_access = 1
        end

        create_request.requested_oplock     = 0xff
        create_request.impersonation_level  = impersonation
        create_request.create_disposition   = disposition
        create_request.name                 = filename

        raw_response  = client.send_recv(create_request, encrypt: @tree_connect_encrypt_data)
        response      = RubySMB::SMB2::Packet::CreateResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::CreateResponse::COMMAND,
            packet:         response
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end

        case @share_type
        when RubySMB::SMB2::Packet::TreeConnectResponse::SMB2_SHARE_TYPE_DISK
          RubySMB::SMB2::File.new(name: filename, tree: self, response: response, encrypt: @tree_connect_encrypt_data)
        when RubySMB::SMB2::Packet::TreeConnectResponse::SMB2_SHARE_TYPE_PIPE
          RubySMB::SMB2::Pipe.new(name: filename, tree: self, response: response)
        # when RubySMB::SMB2::TreeConnectResponse::SMB2_SHARE_TYPE_PRINT
        #   it's a printer!
        else
          raise RubySMB::Error::RubySMBError, 'Unsupported share type'
        end
      end
    end
  end
end
