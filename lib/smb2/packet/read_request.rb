require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.19 SMB2 Read Request](https://msdn.microsoft.com/en-us/library/cc246527.aspx)
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class ReadRequest < Smb2::Packet
    nest :header, RequestHeader

    unsigned :struct_size, 16, default: 49

    # > The requested offset from the start of the SMB2 header, in bytes, at
    #   which to place the data read in the SMB2 READ Response (section 2.2.20).
    #   This value is provided to optimize data placement on the client and is
    #   not binding on the server.
    unsigned :padding, 8

    unsigned :flags, 8

    # > The length, in bytes, of the data to read from the specified file or
    #   pipe. The length of the data being read may be zero bytes
    unsigned :read_length, 32

    # > The offset, in bytes, into the file from which the data MUST be read. If
    #   the read is being executed on a pipe, the Offset MUST be set to 0 by the
    #   client and MUST be ignored by the server.
    unsigned :read_offset, 64

    string :file_id, 128

    # > The minimum number of bytes to be read for this operation to be
    #   successful. If fewer than the minimum number of bytes are read by the
    #   server, the server MUST return an error rather than the bytes read.
    unsigned :minimum_count, 32

    unsigned :channel, 32

    data_buffer :read_channel_info, 16

    rest :buffer

  end
end

