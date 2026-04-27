module RubySMB
  module SMB1
    # An SMB1 connected remote Tree, as returned by a
    # [RubySMB::SMB1::Packet::TreeConnectRequest]
    class Tree
      # Exposes #net_share_enum directly on the tree for callers that need
      # RAP against \PIPE\LANMAN without opening the pipe (Win9x servers do
      # not permit OPEN_ANDX on it).
      include RubySMB::Rap::NetShareEnum

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
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a TreeDisconnectResponse packet
      def disconnect!
        request = RubySMB::SMB1::Packet::TreeDisconnectRequest.new
        request = set_header_fields(request)
        raw_response = client.send_recv(request)
        response = RubySMB::SMB1::Packet::TreeDisconnectResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::TreeDisconnectResponse::COMMAND,
            packet:         response
          )
        end
        response.status_code
      end

      def open_pipe(opts)
        # Make sure we don't modify the caller's hash options
        opts = opts.dup
        opts[:filename] = opts[:filename].dup
        opts[:filename].prepend('\\') unless opts[:filename].start_with?('\\'.encode(opts[:filename].encoding))
        _open(**opts)
      end

      # Open a file on the remote share.
      #
      # @example
      #   tree = client.tree_connect("\\\\192.168.99.134\\Share")
      #   tree.open_file(filename: "myfile")
      #
      # @param filename [String] name of the file to be opened
      # @param flags [BinData::Struct, Hash] flags to setup the request (see {RubySMB::SMB1::Packet::NtCreateAndxRequest})
      # @param options [RubySMB::SMB1::BitField::CreateOptions, Hash] flags that defines how the file should be created
      # @param disposition [Integer] 32-bit field that defines how an already-existing file or a new file needs to be handled (constants are defined in {RubySMB::Dispositions})
      # @param impersonation [Integer] 32-bit field that defines the impersonation level (constants are defined in {RubySMB::ImpersonationLevels})
      # @param read [TrueClass, FalseClass] request a read access
      # @param write [TrueClass, FalseClass] request a write access
      # @param delete [TrueClass, FalseClass] request a delete access
      # @return [RubySMB::SMB1::File] handle to the created file
      # @raise [RubySMB::Error::InvalidPacket] if the response command is not SMB_COM_NT_CREATE_ANDX
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response NTStatus is not STATUS_SUCCESS
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
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a Trans2 packet
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response NTStatus is not STATUS_SUCCESS
      def list(directory: '\\', pattern: '*', unicode: true,
               type: RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo)
        info_standard = (type == RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindInfoStandard)

        find_first_request = RubySMB::SMB1::Packet::Trans2::FindFirst2Request.new
        find_first_request = set_header_fields(find_first_request)
        find_first_request.smb_header.flags2.unicode  = 1 if unicode && !info_standard

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
        t2_params.flags.resume_keys           = 0
        t2_params.information_level           = type::CLASS_LEVEL
        t2_params.filename                    = search_path
        t2_params.search_count                = info_standard ? 255 : 10

        find_first_request = set_find_params(find_first_request)

        raw_response  = client.send_recv(find_first_request)
        response      = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::Trans2::FindFirst2Response::COMMAND,
            packet:         response
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end

        t2p_override, t2d_override = response.win9x_trans2_overrides(raw_response)
        results = if t2d_override
                    response.results(type, unicode: unicode, buffer: t2d_override)
                  else
                    response.results(type, unicode: unicode)
                  end

        effective_params = t2p_override || response.data_block.trans2_parameters
        eos   = effective_params.eos
        sid   = effective_params.sid
        last  = results.last&.file_name

        while eos.zero? && last
          find_next_request = RubySMB::SMB1::Packet::Trans2::FindNext2Request.new
          find_next_request = set_header_fields(find_next_request)
          find_next_request.smb_header.flags2.unicode   = 1 if unicode

          t2_params                             = find_next_request.data_block.trans2_parameters
          t2_params.sid                         = sid
          t2_params.flags.close_eos             = 1
          t2_params.flags.resume_keys           = 0
          t2_params.information_level           = type::CLASS_LEVEL
          t2_params.filename                    = last
          t2_params.search_count                = 10

          find_next_request = set_find_params(find_next_request)

          raw_response  = client.send_recv(find_next_request)
          response      = RubySMB::SMB1::Packet::Trans2::FindNext2Response.read(raw_response)
          unless response.valid?
            raise RubySMB::Error::InvalidPacket.new(
              expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
              expected_cmd:   RubySMB::SMB1::Packet::Trans2::FindNext2Response::COMMAND,
              packet:         response
            )
          end
          unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
            raise RubySMB::Error::UnexpectedStatusCode, response.status_code
          end

          batch = response.results(type, unicode: unicode)
          break if batch.empty?

          results += batch
          eos   = response.data_block.trans2_parameters.eos
          last  = results.last.file_name
        end

        results
      end

      # Create a UNIX symbolic link on the remote share using the CIFS UNIX
      # Extensions SMB_SET_FILE_UNIX_LINK information level (0x0201) via a
      # Trans2 SET_PATH_INFORMATION request.
      #
      # @example
      #   tree = client.tree_connect("\\\\samba\\writable")
      #   tree.set_unix_link(symlink: 'escape', target: '../../../../etc')
      #
      # @param symlink [String] the path, relative to the share, where the
      #   symbolic link file will be created
      # @param target [String] the destination the symbolic link points to
      # @return [WindowsError::ErrorCode] the NTStatus returned by the server
      # @raise [RubySMB::Error::InvalidPacket] if the response is not a Trans2
      #   SET_PATH_INFORMATION response
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response NTStatus
      #   is not STATUS_SUCCESS
      def set_unix_link(symlink:, target:)
        # Samba gates SMB_SET_FILE_UNIX_LINK behind a per-session CIFS UNIX
        # Extensions handshake: query server capabilities, then echo them
        # back via SMB_SET_CIFS_UNIX_INFO. Without this, Samba responds to
        # the symlink request with STATUS_INVALID_LEVEL even when
        # `unix extensions = yes` is set server-side.
        enable_cifs_unix_extensions

        request = RubySMB::SMB1::Packet::Trans2::SetPathInformationRequest.new
        request = set_header_fields(request)
        # CIFS UNIX Extensions paths are raw byte strings, not UTF-16. Clear
        # flags2.unicode so the filename parameter and target data block are
        # emitted as bytes — Samba rejects the UTF-16 variant with
        # STATUS_INVALID_LEVEL.
        request.smb_header.flags2.unicode = 0

        t2_params = request.data_block.trans2_parameters
        t2_params.information_level = RubySMB::SMB1::Packet::Trans2::SetInformationLevel::SMB_SET_FILE_UNIX_LINK
        t2_params.filename = symlink

        encoded_target = target.dup.force_encoding(Encoding::ASCII_8BIT)
        encoded_target << "\x00".b unless encoded_target.end_with?("\x00".b)
        request.data_block.trans2_data.buffer = encoded_target

        request.parameter_block.total_parameter_count = request.parameter_block.parameter_count
        request.parameter_block.total_data_count      = request.parameter_block.data_count
        request.parameter_block.max_parameter_count   = request.parameter_block.parameter_count
        request.parameter_block.max_data_count        = 0

        raw_response = client.send_recv(request)
        response = RubySMB::SMB1::Packet::Trans2::SetPathInformationResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::Trans2::SetPathInformationResponse::COMMAND,
            packet:         response
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end
        response.status_code
      end

      # Sets a few preset header fields that will always be set the same
      # way for Tree operations. This is, the TreeID and Extended Attributes.
      #
      # @param [RubySMB::SMB::Packet] the request packet to modify
      # @return [RubySMB::SMB::Packet] the modified packet.
      def set_header_fields(request)
        request.smb_header.tid        = @id
        request.smb_header.flags2.eas = 1
        request
      end

      # Perform the CIFS UNIX Extensions handshake on this tree: query the
      # server's supported extensions (SMB_QUERY_CIFS_UNIX_INFO) and then
      # echo the version and capability bits back via SMB_SET_CIFS_UNIX_INFO.
      # Samba requires this round-trip to have completed on the current
      # session before it will honor UNIX-extension info levels such as
      # SMB_SET_FILE_UNIX_LINK.
      #
      # @return [WindowsError::ErrorCode] NTStatus of the SET reply
      # @raise [RubySMB::Error::UnexpectedStatusCode] if either leg fails
      def enable_cifs_unix_extensions
        major, minor, capabilities = query_cifs_unix_info
        set_cifs_unix_info(major: major, minor: minor, capabilities: capabilities)
      end

      private

      def query_cifs_unix_info
        request = RubySMB::SMB1::Packet::Trans2::QueryFsInformationRequest.new
        request = set_header_fields(request)
        request.smb_header.flags2.unicode = 0
        request.data_block.trans2_parameters.information_level =
          RubySMB::SMB1::Packet::Trans2::QueryFsInformationLevel::SMB_QUERY_CIFS_UNIX_INFO
        request.parameter_block.total_parameter_count = request.parameter_block.parameter_count
        request.parameter_block.total_data_count      = 0
        request.parameter_block.max_parameter_count   = 0
        request.parameter_block.max_data_count        = 560

        raw_response = client.send_recv(request)
        response = RubySMB::SMB1::Packet::Trans2::QueryFsInformationResponse.read(raw_response)
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end
        info = RubySMB::SMB1::Packet::Trans2::QueryFsInformationLevel::QueryFsCifsUnixInfo.read(
          response.data_block.trans2_data.buffer
        )
        [info.major_version.to_i, info.minor_version.to_i, info.capabilities.to_i]
      end

      def set_cifs_unix_info(major:, minor:, capabilities:)
        request = RubySMB::SMB1::Packet::Trans2::SetFsInformationRequest.new
        request = set_header_fields(request)
        request.smb_header.flags2.unicode = 0
        request.data_block.trans2_parameters.fid               = 0
        request.data_block.trans2_parameters.information_level =
          RubySMB::SMB1::Packet::Trans2::SetFsInformationLevel::SMB_SET_CIFS_UNIX_INFO

        info = RubySMB::SMB1::Packet::Trans2::QueryFsInformationLevel::QueryFsCifsUnixInfo.new
        info.major_version = major
        info.minor_version = minor
        info.capabilities  = capabilities
        request.data_block.trans2_data.buffer = info.to_binary_s

        request.parameter_block.total_parameter_count = request.parameter_block.parameter_count
        request.parameter_block.total_data_count      = request.parameter_block.data_count
        request.parameter_block.max_parameter_count   = request.parameter_block.parameter_count
        request.parameter_block.max_data_count        = 0

        raw_response = client.send_recv(request)
        response = RubySMB::SMB1::Packet::Trans2::SetFsInformationResponse.read(raw_response)
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end
        response.status_code
      end


      def _open(filename:, flags: nil, options: nil, disposition: RubySMB::Dispositions::FILE_OPEN,
                impersonation: RubySMB::ImpersonationLevels::SEC_IMPERSONATE, read: true, write: false, delete: false)
        unless client.server_supports_nt_smbs
          return _open_andx(filename: filename, disposition: disposition, read: read, write: write)
        end
        nt_create_andx_request = RubySMB::SMB1::Packet::NtCreateAndxRequest.new
        nt_create_andx_request = set_header_fields(nt_create_andx_request)

        nt_create_andx_request.parameter_block.ext_file_attributes.normal = 1

        if flags
          nt_create_andx_request.parameter_block.flags = flags
        else
          nt_create_andx_request.parameter_block.flags.request_extended_response = 1
        end

        if options
          nt_create_andx_request.parameter_block.create_options = options
        else
          nt_create_andx_request.parameter_block.create_options.directory_file     = 0
          nt_create_andx_request.parameter_block.create_options.non_directory_file = 1
        end

        if read
          nt_create_andx_request.parameter_block.share_access.share_read     = 1
          nt_create_andx_request.parameter_block.desired_access.read_data    = 1
          nt_create_andx_request.parameter_block.desired_access.read_ea      = 1
          nt_create_andx_request.parameter_block.desired_access.read_attr    = 1
          nt_create_andx_request.parameter_block.desired_access.read_control = 1
        end

        if write
          nt_create_andx_request.parameter_block.share_access.share_write   = 1
          nt_create_andx_request.parameter_block.desired_access.write_data  = 1
          nt_create_andx_request.parameter_block.desired_access.append_data = 1
          nt_create_andx_request.parameter_block.desired_access.write_ea    = 1
          nt_create_andx_request.parameter_block.desired_access.write_attr  = 1
        end

        if delete
          nt_create_andx_request.parameter_block.share_access.share_delete    = 1
          nt_create_andx_request.parameter_block.desired_access.delete_access = 1
        end

        nt_create_andx_request.parameter_block.impersonation_level = impersonation
        nt_create_andx_request.parameter_block.create_disposition  = disposition

        unicode_enabled = nt_create_andx_request.smb_header.flags2.unicode == 1
        nt_create_andx_request.data_block.file_name = add_null_termination(str: filename, unicode: unicode_enabled)

        raw_response = @client.send_recv(nt_create_andx_request)
        response = RubySMB::SMB1::Packet::NtCreateAndxResponse.read(raw_response)
        unless response.valid?
          if response.is_a?(RubySMB::SMB1::Packet::EmptyPacket) &&
               response.smb_header.protocol == RubySMB::SMB1::SMB_PROTOCOL_ID &&
               response.smb_header.command == response.original_command
            raise RubySMB::Error::InvalidPacket.new(
              'The response seems to be an SMB1 NtCreateAndxResponse but an '\
              'error occurs while parsing it. It is probably missing the '\
              'required extended information.'
            )
          end
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::NtCreateAndxResponse::COMMAND,
            packet:         response
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end

        case response.parameter_block.resource_type
        when RubySMB::SMB1::ResourceType::BYTE_MODE_PIPE, RubySMB::SMB1::ResourceType::MESSAGE_MODE_PIPE
          RubySMB::SMB1::Pipe.new(name: filename, tree: self, response: response)
        when RubySMB::SMB1::ResourceType::DISK
          RubySMB::SMB1::File.new(name: filename, tree: self, response: response)
        else
          raise RubySMB::Error::RubySMBError
        end
      end

      # Open a file or pipe using SMB_COM_OPEN_ANDX (0x2D), the LAN Manager 1.0
      # open command used by Windows 95/98/ME and other servers that don't
      # advertise the NT SMBs capability. Accepts the same NT-style disposition
      # constants as {#_open} and maps them to the OpenMode encoding defined in
      # MS-CIFS 2.2.4.41.1.
      #
      # @param filename [String] path to the file on the share
      # @param disposition [Integer] a RubySMB::Dispositions constant
      # @param read [Boolean] request read access
      # @param write [Boolean] request write access
      # @return [RubySMB::SMB1::File, RubySMB::SMB1::Pipe] the opened resource
      # @raise [RubySMB::Error::InvalidPacket] if the response is not valid
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response NTStatus is not STATUS_SUCCESS
      def _open_andx(filename:, disposition:, read: true, write: false)
        request = RubySMB::SMB1::Packet::OpenAndxRequest.new
        request = set_header_fields(request)
        request.smb_header.flags2.unicode = 0

        access = 0x0040 # sharing: deny-nothing
        if read && write
          access |= 0x02
        elsif write
          access |= 0x01
        end

        request.parameter_block.access_mode       = access
        # search_attributes / file_attributes are SMB_FILE_ATTRIBUTES BitField
        # records, not plain uint16s — assign through #read to avoid BinData's
        # each_pair-on-Integer NoMethodError when given a literal mask.
        request.parameter_block.search_attributes.read([0x0016].pack('v'))
        request.parameter_block.file_attributes.read([(write ? 0x0020 : 0x0000)].pack('v'))
        request.parameter_block.open_mode         = nt_disposition_to_open_mode(disposition)

        fname = filename.dup
        fname.prepend('\\') unless fname.start_with?('\\')
        request.data_block.file_name = fname

        raw_response = client.send_recv(request)
        response = RubySMB::SMB1::Packet::OpenAndxResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::OpenAndxResponse::COMMAND,
            packet:         response
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end

        build_open_andx_handle(filename, response)
      end

      # Map an NT-style disposition (RubySMB::Dispositions) to an
      # SMB_COM_OPEN_ANDX OpenMode word. FileExistsOpts is bits 0-1
      # (0=fail, 1=open, 2=truncate); CreateFile is bit 4.
      def nt_disposition_to_open_mode(disposition)
        case disposition
        when RubySMB::Dispositions::FILE_OPEN         then 0x0001
        when RubySMB::Dispositions::FILE_CREATE       then 0x0010
        when RubySMB::Dispositions::FILE_OPEN_IF      then 0x0011
        when RubySMB::Dispositions::FILE_OVERWRITE    then 0x0002
        when RubySMB::Dispositions::FILE_OVERWRITE_IF,
             RubySMB::Dispositions::FILE_SUPERSEDE    then 0x0012
        else
          raise RubySMB::Error::RubySMBError,
                "Unsupported disposition for SMB_COM_OPEN_ANDX: #{disposition}"
        end
      end

      def build_open_andx_handle(filename, response)
        unless response.parameter_block.resource_type == RubySMB::SMB1::ResourceType::DISK
          raise RubySMB::Error::RubySMBError,
                "SMB_COM_OPEN_ANDX resource type 0x#{response.parameter_block.resource_type.to_s(16)} not supported"
        end
        file = RubySMB::SMB1::File.allocate
        file.tree         = self
        file.name         = filename
        file.fid          = response.parameter_block.fid
        file.size         = response.parameter_block.file_data_size
        file.size_on_disk = response.parameter_block.file_data_size
        file.attributes   = response.parameter_block.file_attributes
        file
      end

      # Sets ParameterBlock options for FIND_FIRST2 and
      # FIND_NEXT2 requests. In particular we need to do this
      # to tell the server to ignore the Trans2DataBlock as we are
      # not sending any GEA lists in this instance.
      def set_find_params(request)
        request.parameter_block.data_count             = 0
        request.parameter_block.data_offset            = 0
        request.parameter_block.total_parameter_count  = request.parameter_block.parameter_count
        request.parameter_block.max_parameter_count    = request.parameter_block.parameter_count
        max_data = [16_384, client.server_max_buffer_size].min
        request.parameter_block.max_data_count         = max_data
        request
      end

      # Add null termination to `str` in case it is not already null-terminated.
      #
      # @str [String] the string to be null-terminated
      # @unicode [TrueClass, FalseClass] True if the null-termination should be Unicode encoded
      # @return [String] the null-terminated string
      def add_null_termination(str:, unicode: false)
        null_termination = unicode ? "\x00".encode('UTF-16LE') : "\x00"
        if str.end_with?(null_termination)
          return str
        else
          return str + null_termination
        end
      end

    end
  end
end
