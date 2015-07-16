require 'smb2/packet'

# @see Smb2::Packet::QUERY_DIRECTORY_FLAGS
class Smb2::Packet::QueryDirectoryRequest < Smb2::Packet::Request

  # A key in {Smb2::COMMANDS}
  COMMAND = :QUERY_DIRECTORY

  unsigned :struct_size, 16, default: 33

  # Should be one of the {FILE_INFORMATION_CLASSES} constants
  # @see FILE_INFORMATION_CLASSES
  unsigned :file_info_class, 8

  # Should be one of the {QUERY_DIRECTORY_FLAGS} constants
  #
  # > Flags indicating how the query directory operation MUST be processed.
  #   This field MUST be a logical OR of the following values, or zero if none
  #   are selected:
  #
  # | Value | Meaning
  # | SMB2_RESTART_SCANS 0x01 | The server MUST restart the enumeration from the beginning, but the search pattern is not changed.
  # | SMB2_RETURN_SINGLE_ENTRY 0x02 | The server MUST only return the first entry of the search results.
  # | SMB2_INDEX_SPECIFIED 0x04 | The server SHOULD return entries beginning at the byte number specified by FileIndex.
  # | SMB2_REOPEN 0x10 | The server MUST restart the enumeration from the beginning, and the search pattern MUST be changed to the provided value. This often involves silently closing and reopening the directory on the server side.
  #
  unsigned :flags, 8

  unsigned :file_index, 32

  string :file_id, 128

  data_buffer :file_name, 16

  unsigned :output_buffer_length, 32

  rest :buffer

end
