require 'ruby_smb/smb2/packet'


# [Section 2.2.22 SMB2 Write Response](http://msdn.microsoft.com/en-us/library/cc246533.aspx)
#
# [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
class RubySMB::Smb2::Packet::WriteResponse < RubySMB::Smb2::Packet::Response
  COMMAND = :WRITE

  unsigned :struct_size, 16, default: 17
  unsigned :reserved, 16
  unsigned :byte_count, 32
  unsigned :remaining, 32

  data_buffer :channel_info

  rest :buffer

end
