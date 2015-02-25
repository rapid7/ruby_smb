require 'smb2/packet'

class Smb2::Packet

  # [[MS-SMB2] 2.2.38 SMB2 QUERY_INFO Response](https://msdn.microsoft.com/en-us/library/cc246559.aspx)
  class QueryInfoResponse < Smb2::Packet
    nest :header, ResponseHeader
    unsigned :struct_size, 16, default: 9

    data_buffer :output_buffer, 32

    rest :buffer
  end

end


