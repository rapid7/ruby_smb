require 'ruby_smb/smb2/packet'

# [Section 2.2.16 SMB2 CLOSE Response](https://msdn.microsoft.com/en-us/library/cc246524.aspx)
class RubySMB::SMB2::Packet::CloseResponse < RubySMB::SMB2::Packet::Response
  COMMAND = :CLOSE

  unsigned :struct_size, 16, default: 60
  unsigned :flags, 16
  unsigned :last_access_time, 64
  unsigned :last_write_time, 64
  unsigned :last_change_time, 64
  unsigned :allocation_size, 64
  unsigned :end_of_file, 64
  unsigned :file_attributes, 32
end
