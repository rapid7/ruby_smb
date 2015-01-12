require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.21 SMB2 Write Request](http://msdn.microsoft.com/en-us/library/cc246532.aspx)
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class WriteRequest < Smb2::Packet
    nest :header, RequestHeader
    unsigned :struct_size, 16, default: 49

    data_buffer :data, 32

    # Where to begin the write, an offset from the beginning of the file. Must
    # be 0 for named pipes.
    unsigned :file_offset, 64
    string :file_id, 128
    unsigned :channel, 32
    unsigned :remaining_bytes, 32

    data_buffer :channel_info, 16

    unsigned :flags, 32

    rest :buffer

  end
end
