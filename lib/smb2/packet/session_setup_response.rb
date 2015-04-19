# Implements [Section 2.2.6 SMB2 SESSION_SETUP Response](https://msdn.microsoft.com/en-us/library/cc246564.aspx)
class Smb2::Packet::SessionSetupResponse < Smb2::Packet::Generic
  nest :header, Smb2::Packet::ResponseHeader
  unsigned :struct_size, 16
  unsigned :flags, 16
  data_buffer :security_blob

  rest :buffer

  FLAGS = {
    NULL_SESSION:  0x0000_0010,
    GUEST_SESSION: 0x0000_0001
  }.freeze

  FLAG_NAMES = FLAGS.keys

end
