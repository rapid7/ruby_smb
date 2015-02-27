require 'bit-struct'

module Smb2
  module Packet
    # Raised when flags for a given packet are incorrect or incomplete
    class InvalidFlagError < StandardError; end

    autoload :Generic, 'smb2/packet/generic'

    autoload :CloseRequest, "smb2/packet/close_request"
    autoload :CloseResponse, "smb2/packet/close_response"

    autoload :CreateRequest, "smb2/packet/create_request"
    autoload :CreateResponse, "smb2/packet/create_response"

    autoload :IoctlRequest, "smb2/packet/ioctl_request"
    autoload :IoctlResponse, "smb2/packet/ioctl_response"

    autoload :NegotiateRequest, "smb2/packet/negotiate_request"
    autoload :NegotiateResponse, "smb2/packet/negotiate_response"

    autoload :QueryInfoRequest, "smb2/packet/query_info_request"
    autoload :QueryInfoResponse, "smb2/packet/query_info_response"

    autoload :ReadRequest, "smb2/packet/read_request"
    autoload :ReadResponse, "smb2/packet/read_response"

    autoload :RequestHeader, "smb2/packet/request_header"
    autoload :ResponseHeader, "smb2/packet/response_header"

    autoload :SessionSetupRequest, "smb2/packet/session_setup_request"
    autoload :SessionSetupResponse, "smb2/packet/session_setup_response"

    autoload :TreeConnectRequest, "smb2/packet/tree_connect_request"
    autoload :TreeConnectResponse, "smb2/packet/tree_connect_response"

    autoload :WriteRequest, "smb2/packet/write_request"
    autoload :WriteResponse, "smb2/packet/write_response"

  QUERY_INFO_TYPES = {
    FILE: 0x01,
    FILESYSTEM: 0x02,
    SECURITY: 0x03,
    QUOTA: 0x04
  }.freeze

  # Used in {QueryInfoRequest} packets' {QueryInfoRequest#file_info_class} field.
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

  # For {SessionSetupRequest} packets' {SessionSetupRequest#security_mode}
  # field.
  #
  # @see https://msdn.microsoft.com/en-us/library/cc246563.aspx
  SECURITY_MODES = {
    SIGNING_ENABLED: 0x1,
    SIGNING_REQUIRED: 0x2
  }.freeze
  end
end
