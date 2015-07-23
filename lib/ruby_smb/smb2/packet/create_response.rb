require 'ruby_smb/smb2/packet'

# [Section 2.2.14 SMB2 CREATE Response](http://msdn.microsoft.com/en-us/library/cc246512.aspx)
#
# [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
class RubySMB::Smb2::Packet::CreateResponse < RubySMB::Smb2::Packet::Response
  COMMAND = :CREATE

  # "The server MUST set this field to 89, indicating the size of the
  # request structure, not including the header. The client MUST set it to
  # this value regardless of how long Buffer[] actually is in the request
  # being sent."
  unsigned :struct_size, 16, default: 89

  unsigned :oplock, 8

  # "If the server implements the SMB 3.x dialect family, this field MUST be
  # constructed using the following value. Otherwise, this field MUST NOT be
  # used and MUST be reserved."
  unsigned :flags, 8, default: 0

  unsigned :create_action, 32
  unsigned :creation_time, 64
  unsigned :last_action_time, 64
  unsigned :last_write_time, 64
  unsigned :change_time, 64
  unsigned :allocation_size, 64
  unsigned :end_of_file, 64
  unsigned :file_attributes, 32
  unsigned :reserved2, 32

  string :file_id, 128

  unsigned :create_contexts_offset, 32
  unsigned :create_contexts_length, 32

end
