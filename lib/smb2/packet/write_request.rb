require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.21 SMB2 Write Request](http://msdn.microsoft.com/en-us/library/cc246532.aspx)
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class WriteRequest < Smb2::Packet
    nest :header, RequestHeader
    unsigned :struct_size, 16, endian: 'little', default: 49

    unsigned :data_offset, 16, endian: 'little'
    unsigned :data_length, 32, endian: 'little'

    # where to begin the write, an offset from the beginning of the file. must
    # be 0 for named pipes
    unsigned :file_offset, 64, endian: 'little'

    string :file_id, 128

    unsigned :channel, 32, endian: 'little'
    unsigned :remaining_bytes, 32, endian: 'little'
    data_buffer :channel_info
    unsigned :flags, 32, endian: 'little'

  end
end
