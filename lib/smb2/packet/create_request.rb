# Implements [Section 2.2.13 SMB2 CREATE Request](http://msdn.microsoft.com/en-us/library/cc246502.aspx)
# [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
class Smb2::Packet::CreateRequest < Smb2::Packet::Generic
  nest :header, Smb2::Packet::RequestHeader
  # "The client MUST set this field to 57, indicating the size of the
  # request structure, not including the header. The client MUST set it to
  # this value regardless of how long Buffer[] actually is in the request
  # being sent."
  unsigned :struct_size, 16, default: 57

  unsigned :oplock, 8

  # "This field MUST NOT be used and MUST be reserved. The client MUST set
  # this to 0, and the server MUST ignore it."
  unsigned :security_flags, 8, default: 0

  unsigned :impersonation, 32

  unsigned :access_mask, 32

  unsigned :create_flags, 64

  # The documentation says this should be 8 bytes, but I'm only seeing 4 on
  # the wire.
  unsigned :reserved, 32, default: 0

  unsigned :desired_access, 32
  unsigned :file_attributes, 32
  unsigned :share_access, 32
  unsigned :disposition, 32
  unsigned :create_options, 32

  data_buffer :filename
  unsigned :create_contexts_offset, 32
  unsigned :create_contexts_length, 32

  rest :buffer

end

