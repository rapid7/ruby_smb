require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.22 SMB2 Read Response](https://msdn.microsoft.com/en-us/library/cc246531.aspx)
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class ReadResponse < Smb2::Packet
    nest :header, ResponseHeader
    unsigned :struct_size, 16, default: 17

    # The result of the read operation.
    #
    # XXX: the documentation says this should be 1 byte with 1 byte of
    # 'reserved' between length and offset. Consider making data_buffer
    # configurable for the offset bitlength. In practice, the reserved byte is
    # always 0. Further, wireshark displays data_offset as a 16-bit value,
    # giving me a little more confidence that treating it similarly is fine.
    data_buffer :data, 16

    # > The length, in bytes, of the data being sent on the Channel specified in
    #   the request.
    unsigned :data_remaining, 32

    # > This field MUST NOT be used and MUST be reserved. The server MUST set
    #   this to 0, and the client MUST ignore it on receipt.
    unsigned :reserved2, 32

    rest :buffer

  end
end

