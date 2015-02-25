require 'smb2'
require 'bit-struct'

# A PDU for the SMB2 protocol
#
# [[MS-SMB2] 2.2 Message Syntax](https://msdn.microsoft.com/en-us/library/cc246497.aspx)
class Smb2::Packet < BitStruct
  class InvalidFlagError < StandardError; end

  autoload :CloseRequest, "smb2/packet/close_request"
  autoload :CloseResponse, "smb2/packet/close_response"

  autoload :CreateRequest, "smb2/packet/create_request"
  autoload :CreateResponse, "smb2/packet/create_response"

  autoload :NegotiateRequest, "smb2/packet/negotiate_request"
  autoload :NegotiateResponse, "smb2/packet/negotiate_response"

  autoload :IoctlRequest, "smb2/packet/ioctl_request"
  autoload :IoctlResponse, "smb2/packet/ioctl_response"

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

  default_options endian: 'little'

  # List of all {.data_buffer} field names
  # @return [Array<String>]
  def self.data_buffer_fields
    @data_buffer_fields ||= []
  end

  # Define a data buffer consisting of an offset, 16- or 32-bit length, and a
  # value of `length` bytes at the end of the packet. Will create attributes
  # for the thing itself as well as one for `<name>_length` and
  # `<name>_offset`
  #
  # @param name [Symbol]
  # @param bit_length [Fixnum] length in bits of the buffer's `length` field.
  # @option opts [Fixnum] :padding (0) number of bits to align after the length,
  # @option opts [Fixnum] :offset_bitlength (16) length in bits of the
  #   buffer's `offset` field.
  # @return [void]
  def self.data_buffer(name, bit_length=16, opts={})
    (@data_buffer_fields ||= []) << name

    self.unsigned "#{name}_offset", (opts[:offset_bitlength] || 16), endian: 'little'
    self.unsigned "#{name}_padding", opts[:padding] if opts.has_key?(:padding)
    self.unsigned "#{name}_length", bit_length, endian: 'little'

    class_eval do

      define_method(name) do
        field_offset = self.send("#{name}_offset")
        field_length = self.send("#{name}_length")
        # Must use #to_s so we get the whole packet packed because offset is from
        # beginning of header.
        to_s.slice(field_offset, field_length)
      end

      define_method("#{name}=") do |other|
        @data_buffers[name] = other
        recalculate
      end

    end

    self
  end

  # @see BitStruct#initialize
  def initialize(*args)
    @data_buffers = {}
    super do
      if !self.class.data_buffer_fields.empty?
        self.class.data_buffer_fields.each do |buffer_name|
          @data_buffers[buffer_name] = self.send(buffer_name) || ""
        end
        recalculate
      end
      yield self if block_given?
    end
  end

  # A generic flag checking method. Subclasses should have a field named
  # `flags`, and constants `FLAGS` and `FLAG_NAMES`.
  #
  # @param flag [Symbol] a key in `FLAGS`
  def has_flag?(flag)
    raise InvalidFlagError, flag.to_s unless self.class::FLAG_NAMES.include?(flag)
    (flags & self.class::FLAGS[flag]) == self.class::FLAGS[flag]
  end

  # Fix the length and offset fields for all {.data_buffer data buffer fields}
  #
  # @return [self]
  def recalculate
    offset = self.header.header_len + (struct_size & ~1)
    new_buffer = ""

    self.class.data_buffer_fields.each do |buffer_name|
      new_size = @data_buffers[buffer_name].size
      if new_size.zero?
        self.send("#{buffer_name}_offset=", 0)
      else
        new_buffer << @data_buffers[buffer_name]
        self.send("#{buffer_name}_length=", new_size)
        self.send("#{buffer_name}_offset=", offset)
      end
      offset += new_size
    end
    self.buffer = new_buffer

    self
  end

end
