require 'ruby_smb/smb2/packet'

# [[MS-SMB2] 2.2.38 SMB2 QUERY_INFO Response](https://msdn.microsoft.com/en-us/library/cc246559.aspx)
class RubySMB::Smb2::Packet::QueryInfoResponse < RubySMB::Smb2::Packet::Response
  COMMAND = :QUERY_INFO

  unsigned :struct_size, 16, default: 9

  data_buffer :output_buffer, 32

  rest :buffer
end