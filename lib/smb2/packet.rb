require 'bit-struct'

# A PDU for the SMB2 protocol
#
# [[MS-SMB2] 2.2 Message Syntax](https://msdn.microsoft.com/en-us/library/cc246497.aspx)
module Smb2
  module Packet

    # Raised when {#has_flag?} is given something that isn't a member of
    # `FLAG_NAMES`
    class InvalidFlagError < StandardError; end

    require "smb2/packet/generic"

    autoload :CloseRequest, "smb2/packet/close_request"
    autoload :CloseResponse, "smb2/packet/close_response"

    autoload :EchoRequest, "smb2/packet/echo_request"
    autoload :EchoResponse, "smb2/packet/echo_response"

    autoload :CreateRequest, "smb2/packet/create_request"
    autoload :CreateResponse, "smb2/packet/create_response"

    autoload :NegotiateRequest, "smb2/packet/negotiate_request"
    autoload :NegotiateResponse, "smb2/packet/negotiate_response"

    autoload :IoctlRequest, "smb2/packet/ioctl_request"
    autoload :IoctlResponse, "smb2/packet/ioctl_response"

    autoload :Query, "smb2/packet/query"

    autoload :QueryInfoRequest, "smb2/packet/query_info_request"
    autoload :QueryInfoResponse, "smb2/packet/query_info_response"

    autoload :QueryDirectoryRequest, "smb2/packet/query_directory_request"
    autoload :QueryDirectoryResponse, "smb2/packet/query_directory_response"

    autoload :ReadRequest, "smb2/packet/read_request"
    autoload :ReadResponse, "smb2/packet/read_response"

    autoload :Request, "smb2/packet/request"
    autoload :Response, "smb2/packet/response"

    autoload :SessionSetupRequest, "smb2/packet/session_setup_request"
    autoload :SessionSetupResponse, "smb2/packet/session_setup_response"

    autoload :TreeConnectRequest, "smb2/packet/tree_connect_request"
    autoload :TreeConnectResponse, "smb2/packet/tree_connect_response"

    autoload :WriteRequest, "smb2/packet/write_request"
    autoload :WriteResponse, "smb2/packet/write_response"

    ##
    # Constants
    ##

    # Used in {CreateRequest#disposition}
    # @note Ordered by value
    CREATE_DISPOSITIONS = {
      # If the file already exists, supersede it. Otherwise, create the file.
      # This value SHOULD NOT be used for a printer object.<30>
      FILE_SUPERSEDE: 0x0000_0000,
      # If the file already exists, return success; otherwise, fail the
      # operation. MUST NOT be used for a printer object.
      FILE_OPEN: 0x0000_0001,
      # If the file already exists, fail the operation; otherwise, create the
      # file.
      FILE_CREATE: 0x0000_0002,
      # Open the file if it already exists; otherwise, create the file. This
      # value SHOULD NOT be used for a printer object.<31>
      FILE_OPEN_IF: 0x0000_0003,
      # Overwrite the file if it already exists; otherwise, fail the operation. MUST
      # NOT be used for a printer object.
      FILE_OVERWRITE: 0x0000_0004,
      # Overwrite the file if it already exists; otherwise, create the file.
      # This value SHOULD NOT be used for a printer object.<32>
      FILE_OVERWRITE_IF: 0x0000_0005,
    }.freeze

    # Used in {CreateRequest#create_options}
    #
    # @see https://msdn.microsoft.com/en-us/library/cc246502.aspx
    # @note Ordered by value
    CREATE_OPTIONS = {
      FILE_DIRECTORY_FILE: 0x0000_0001,
      FILE_WRITE_THROUGH: 0x0000_0002,
      FILE_SEQUENTIAL_ONLY: 0x0000_0004,
      FILE_NO_INTERMEDIATE_BUFFERING: 0x0000_0008,
      FILE_SYNCHRONOUS_IO_ALERT: 0x0000_0010,
      FILE_SYNCHRONOUS_IO_NONALERT: 0x0000_0020,
      FILE_NON_DIRECTORY_FILE: 0x0000_0040,
      FILE_COMPLETE_IF_OPLOCKED: 0x0000_0100,
      FILE_NO_EA_KNOWLEDGE: 0x0000_0200,
      FILE_RANDOM_ACCESS: 0x0000_0800,
      FILE_DELETE_ON_CLOSE: 0x0000_1000,
      FILE_OPEN_BY_FILE_ID: 0x0000_2000,
      FILE_OPEN_FOR_BACKUP_INTENT: 0x0000_4000,
      FILE_NO_COMPRESSION: 0x0000_8000,
      FILE_OPEN_REMOTE_INSTANCE: 0x0000_0400,
      FILE_OPEN_REQUIRING_OPLOCK: 0x0001_0000,
      FILE_DISALLOW_EXCLUSIVE: 0x0002_0000,
      FILE_RESERVE_OPFILTER: 0x0010_0000,
      FILE_OPEN_REPARSE_POINT: 0x0020_0000,
      FILE_OPEN_NO_RECALL: 0x0040_0000,
      FILE_OPEN_FOR_FREE_SPACE_QUERY: 0x0080_0000,
    }.freeze

    # Used in {CreateRequest#desired_access} when opening a file, pipe, printer.
    # For access mask values to use when opening a directory, see
    # {DIRECTORY_ACCESS_MASK}.
    #
    # From the documentation ([2.2.13.1.1 File_Pipe_Printer_Access_Mask](https://msdn.microsoft.com/en-us/library/cc246802.aspx)):
    #
    # > The SMB2 Access Mask Encoding in SMB2 is a 4-byte bit field value that
    #   contains an array of flags. An access mask can specify access for one of
    #   two basic groups: either for a file, pipe, or printer (specified in
    #   section 2.2.13.1.1) or for a directory (specified in section 2.2.13.1.2).
    #
    # @see DIRECTORY_ACCESS_MASK
    # @note Ordered by value
    FILE_ACCESS_MASK = {
      # This value indicates the right to read data from the file or named pipe.
      FILE_READ_DATA: 0x0000_0001,
      # This value indicates the right to write data into the file or named pipe
      # beyond the end of the file.
      FILE_WRITE_DATA: 0x0000_0002,
      # This value indicates the right to append data into the file or named
      # pipe.
      FILE_APPEND_DATA: 0x0000_0004,
      # This value indicates the right to read the extended attributes of the
      # file or named pipe.
      FILE_READ_EA: 0x0000_0008,
      # This value indicates the right to write or change the extended
      # attributes to the file or named pipe.
      FILE_WRITE_EA: 0x0000_0010,
      # This value indicates the right to delete entries within a directory.
      FILE_DELETE_CHILD: 0x0000_0040,
      # This value indicates the right to execute the file.
      FILE_EXECUTE: 0x0000_0020,
      # This value indicates the right to read the attributes of the file.
      FILE_READ_ATTRIBUTES: 0x0000_0080,
      # This value indicates the right to change the attributes of the file.
      FILE_WRITE_ATTRIBUTES: 0x0000_0100,
      # This value indicates the right to delete the file.
      DELETE: 0x0001_0000,
      # This value indicates the right to read the security descriptor for the
      # file or named pipe.
      READ_CONTROL: 0x0002_0000,
      # This value indicates the right to change the discretionary access
      # control list (DACL) in the security descriptor for the file or named
      # pipe. For the DACL data structure, see ACL in [MS-DTYP].
      WRITE_DAC: 0x0004_0000,
      # This value indicates the right to change the owner in the security
      # descriptor for the file or named pipe.
      WRITE_OWNER: 0x0008_0000,
      # SMB2 clients set this flag to any value.<40> SMB2 servers SHOULD<41>
      # ignore this flag.
      SYNCHRONIZE: 0x0010_0000,
      # This value indicates the right to read or change the system access
      # control list (SACL) in the security descriptor for the file or named
      # pipe. For the SACL data structure, see ACL in [MS-DTYP].<42>
      ACCESS_SYSTEM_SECURITY: 0x0100_0000,
      # This value indicates that the client is requesting an open to the file
      # with the highest level of access the client has on this file. If no
      # access is granted for the client on this file, the server MUST fail the
      # open with STATUS_ACCESS_DENIED.
      MAXIMUM_ALLOWED: 0x0200_0000,
      # This value indicates a request for all the access flags that are
      # previously listed except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY.
      GENERIC_ALL: 0x1000_0000,
      # This value indicates a request for the following combination of access
      # flags listed above: FILE_READ_ATTRIBUTES| FILE_EXECUTE| SYNCHRONIZE|
      # READ_CONTROL.
      GENERIC_EXECUTE: 0x2000_0000,
      # This value indicates a request for the following combination of access
      # flags listed above: FILE_WRITE_DATA| FILE_APPEND_DATA|
      # FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL.
      GENERIC_WRITE: 0x4000_0000,
      # This value indicates a request for the following combination of access
      # flags listed above: FILE_READ_DATA| FILE_READ_ATTRIBUTES| FILE_READ_EA|
      # SYNCHRONIZE| READ_CONTROL.
      GENERIC_READ: 0x8000_0000,
    }.freeze

    # [2.2.13.1.2 Directory_Access_Mask](https://msdn.microsoft.com/en-us/library/cc246801.aspx)
    # @todo
    DIRECTORY_ACCESS_MASK = {
    }.freeze

    # Used in {QueryInfoRequest} packets' {QueryInfoRequest#file_info_class} field.
    # Also used in {QueryDirectoryRequest} packets' {QueryDirectoryRequest#file_info_class} field.
    #
    # See [[MS-FSCC] 2.4 File Information Classes](https://msdn.microsoft.com/en-us/library/cc232064.aspx)
    # for a description of these values.
    FILE_INFORMATION_CLASSES = {
      FileAccessInformation:  8, # Query
      FileAlignmentInformation:  17, # Query
      FileAllInformation:  18, # Query
      FileAllocationInformation:  19, # Set
      FileAlternateNameInformation:  21, # Query
      FileAttributeTagInformation:  35, # Query
      FileBasicInformation:  4, # Query, Set
      FileBothDirectoryInformation:  3, # Query
      FileCompressionInformation:  28, # Query
      FileDirectoryInformation:  1, # Query
      FileDispositionInformation:  13, # Set
      FileEaInformation:  7, # Query
      FileEndOfFileInformation:  20, # Set
      FileFullDirectoryInformation:  2, # Query
      FileFullEaInformation:  15, # Query, Set
      FileHardLinkInformation:  46, # LOCAL<71>
      FileIdBothDirectoryInformation:  37, # Query
      FileIdFullDirectoryInformation:  38, # Query
      FileIdGlobalTxDirectoryInformation:  50, # LOCAL<72>
      FileInternalInformation:  6, # Query
      FileLinkInformation:  11, # Set
      FileMailslotQueryInformation:  26, # LOCAL<73>
      FileMailslotSetInformation:  27, # LOCAL<74>
      FileModeInformation:  16, # Query, Set<75>
      FileMoveClusterInformation:  31, # <76>
      FileNameInformation:  9, # LOCAL<77>
      FileNamesInformation:  12, # Query
      FileNetworkOpenInformation:  34, # Query
      FileNormalizedNameInformation:  48, # <78>
      FileObjectIdInformation:  29, # LOCAL<79>
      FilePipeInformation:  23, # Query, Set
      FilePipeLocalInformation:  24, # Query
      FilePipeRemoteInformation:  25, # Query
      FilePositionInformation:  14, # Query, Set
      FileQuotaInformation:  32, # Query, Set<80>
      FileRenameInformation:  10, # Set
      FileReparsePointInformation:  33, # LOCAL<81>
      FileSfioReserveInformation:  44, # LOCAL<82>
      FileSfioVolumeInformation:  45, # <83>
      FileShortNameInformation:  40, # Set
      FileStandardInformation:  5, # Query
      FileStandardLinkInformation:  54, # LOCAL<84>
      FileStreamInformation:  22, # Query
      FileTrackingInformation:  36, # LOCAL<85>
      FileValidDataLengthInformation:  39, # Set
    }.freeze

    # Values for {CreateRequest#impersonation}
    #
    # Value                     | Meaning
    # --------------------------+------------------------
    # Anonymous      0x00000000 | The application-requested impersonation level is Anonymous.
    # Identification 0x00000001 | The application-requested impersonation level is Identification.
    # Impersonation  0x00000002 | The application-requested impersonation level is Impersonation.
    # Delegate       0x00000003 | The application-requested impersonation level is Delegate.
    #
    # @see https://msdn.microsoft.com/en-us/library/cc246502.aspx
    IMPERSONATION_LEVELS = {
      ANONYMOUS: 0x0,
      IDENTIFICATION: 0x1,
      IMPERSONATION: 0x2,
      DELEGATE: 0x3,
    }.freeze

    # Values for {QueryInfoRequest#info_type}
    # @see https://msdn.microsoft.com/en-us/library/cc246557.aspx
    QUERY_INFO_TYPES = {
      # SMB2_0_INFO_FILE
      FILE: 0x01,
      # SMB2_0_INFO_FILESYSTEM
      FILESYSTEM: 0x02,
      # SMB2_0_INFO_SECURITY
      SECURITY: 0x03,
      # SMB2_0_INFO_QUOTA
      QUOTA: 0x04
    }.freeze

    # Values for {QueryDirectoryRequest#flags}
    # @see https://msdn.microsoft.com/en-us/library/cc246551.aspx
    QUERY_DIRECTORY_FLAGS = {
      # SMB2_RESTART_SCANS
      RESTART_SCANS: 0x01,
      # SMB2_RETURN_SINGLE_ENTRY
      RETURN_SINGLE_ENTRY: 0x02,
      # SMB2_INDEX_SPECIFIED
      INDEX_SPECIFIED: 0x04,
      # SMB2_REOPEN
      REOPEN: 0x10
    }.freeze

    # For {SessionSetupRequest} packets' {SessionSetupRequest#security_mode}
    # field.
    #
    # @see https://msdn.microsoft.com/en-us/library/cc246563.aspx
    SECURITY_MODES = {
      SIGNING_ENABLED: 0x1,
      SIGNING_REQUIRED: 0x2
    }.freeze

    SHARE_ACCESS = {
      FILE_SHARE_READ: 1,
      FILE_SHARE_WRITE: 2,
      FILE_SHARE_DELETE: 4,
    }.freeze

    HEADER_FLAGS = {
      REPLAY:   0x0200_0000,
      DFS:      0x0100_0000,
      SIGNING:  0x0000_0008,
      CHAINED:  0x0000_0004,
      ASYNC:    0x0000_0002,
      RESPONSE: 0x0000_0001,
    }.freeze

    HEADER_FLAG_NAMES = HEADER_FLAGS.keys

    # Take data from the wire and determine the type of packet it is.
    #
    # @param data [String] packet data from the wire
    # @return [Smb2::Packet::Generic] a subclass of {Generic}
    def self.parse(data)
      generic = Generic.new(data)

      case [ generic.command, generic.response? ]

      when [ COMMANDS[:NEGOTIATE], true ]
        NegotiateResponse.new(generic)
      when [ COMMANDS[:NEGOTIATE], false ]
        NegotiateRequest.new(generic)

      when [ COMMANDS[:SESSION_SETUP], true ]
        SessionSetupResponse.new(generic)
      when [ COMMANDS[:SESSION_SETUP], false ]
        SessionSetupRequest.new(generic)

      when [ COMMANDS[:TREE_CONNECT], true ]
        TreeConnectResponse.new(generic)
      when [ COMMANDS[:TREE_CONNECT], false ]
        TreeConnectRequest.new(generic)

      when [ COMMANDS[:CREATE], true ]
        CreateResponse.new(generic)
      when [ COMMANDS[:CREATE], false ]
        CreateRequest.new(generic)

      when [ COMMANDS[:CLOSE], true ]
        CloseResponse.new(generic)
      when [ COMMANDS[:CLOSE], false ]
        CloseRequest.new(generic)

      when [ COMMANDS[:READ], true ]
        ReadResponse.new(generic)
      when [ COMMANDS[:READ], false ]
        ReadRequest.new(generic)

      when [ COMMANDS[:WRITE], true ]
        WriteResponse.new(generic)
      when [ COMMANDS[:WRITE], false ]
        WriteRequest.new(generic)

      when [ COMMANDS[:QUERY_DIRECTORY_FLAGS], true ]
        QueryDirectoryResponse.new(generic)
      when [ COMMANDS[:QUERY_DIRECTORY_FLAGS], false ]
        QueryDirectoryRequest.new(generic)

      when [ COMMANDS[:QUERY_INFO], true ]
        QueryInfoResponse.new(generic)
      when [ COMMANDS[:QUERY_INFO], false ]
        QueryInfoRequest.new(generic)

      else
        raise "Unimplemented command"
      end
    end

  end
end
