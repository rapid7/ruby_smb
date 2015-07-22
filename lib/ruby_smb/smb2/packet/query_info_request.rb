require 'ruby_smb/smb2/packet'

# @see Smb2::Packet::QUERY_INFO_TYPES
class Smb2::Packet::QueryInfoRequest < Smb2::Packet::Request

  # A key in {Smb2::COMMANDS}
  COMMAND = :QUERY_INFO

  unsigned :struct_size, 16, default: 41

  # Should be one of the {QUERY_INFO_TYPES} constants
  #
  # > The type of information queried. This field MUST contain one of the
  #   following values:
  #
  # | Value | Meaning
  # | SMB2_0_INFO_FILE 0x01 | The file information is requested.
  # | SMB2_0_INFO_FILESYSTEM 0x02 | The underlying object store information is requested.
  # | SMB2_0_INFO_SECURITY 0x03 | The security information is requested.
  # | SMB2_0_INFO_QUOTA 0x04 | The underlying object store quota information is requested.
  #
  unsigned :info_type, 8

  # Should be one of the {FILE_INFORMATION_CLASSES} constants
  # @see FILE_INFORMATION_CLASSES
  unsigned :file_info_class, 8

  unsigned :output_buffer_length, 32

  data_buffer :input_buffer, 32, padding: 16

  unsigned :additional_information, 32
  unsigned :flags, 32

  string :file_id, 128

  rest :buffer
end
