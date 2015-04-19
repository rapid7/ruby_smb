# Implements [Section 2.2.22 SMB2 Read Response](https://msdn.microsoft.com/en-us/library/cc246531.aspx)
# [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
class Smb2::Packet::ReadResponse < Smb2::Packet::Generic
  nest :header, Smb2::Packet::ResponseHeader
  unsigned :struct_size, 16, default: 17

  # The result of the read operation.
  #
  # @note The documentation says this should be 1 byte with 1 byte of
  # 'reserved' between length and offset. Wireshark displays data_offset as
  # a 16-bit value, but the padding is always 0 in practice, so it works
  # out.
  data_buffer :data, 16, offset_bitlength: 8, padding: 8

  # > The length, in bytes, of the data being sent on the Channel specified in
  #   the request.
  unsigned :data_remaining, 32

  # > This field MUST NOT be used and MUST be reserved. The server MUST set
  #   this to 0, and the client MUST ignore it on receipt.
  unsigned :reserved2, 32

  rest :buffer

end

