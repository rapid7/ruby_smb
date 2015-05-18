require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.22 SMB2 Write Response](http://msdn.microsoft.com/en-us/library/cc246533.aspx)
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class WriteResponse < Smb2::Packet
    nest :header, ResponseHeader
    unsigned :struct_size, 16, default: 17
    unsigned :reserved, 16
    unsigned :byte_count, 32
    unsigned :remaining, 32

    data_buffer :channel_info

    rest :buffer

  end
end
