require 'smb2/packet'

# [[MS-SMB2] 2.2.34 SMB2 QUERY_DIRECTORY Response](https://msdn.microsoft.com/en-us/library/cc246552.aspx)
class Smb2::Packet::QueryDirectoryResponse < Smb2::Packet::Response
  COMMAND = :QUERY_DIRECTORY

  unsigned :struct_size, 16, default: 9

  data_buffer :output_buffer, 32

  rest :buffer

end
