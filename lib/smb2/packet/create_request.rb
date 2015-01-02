require 'smb2/packet'

class Smb2::Packet
  # @see http://msdn.microsoft.com/en-us/library/cc246794.aspx
  # @see http://msdn.microsoft.com/en-us/library/cc246502.aspx
  class CreateRequest < Smb2::Packet
    nest :header, RequestHeader
    # "The client MUST set this field to 57, indicating the size of the
    # request structure, not including the header. The client MUST set it to
    # this value regardless of how long Buffer[] actually is in the request
    # being sent."
    unsigned :struct_size, 16, endian: 'little', default: 57

    unsigned :oplock, 8

    # "This field MUST NOT be used and MUST be reserved. The client MUST set
    # this to 0, and the server MUST ignore it."
    unsigned :security_flags, 8, default: 0

    unsigned :impersonation, 32, endian: 'little'

    unsigned :access_mask, 32, endian: 'little'

    unsigned :create_flags, 64, endian: 'little'

    # The documentation says this should be 8 bytes, but I'm only seeing 4 on
    # the wire.
    unsigned :reserved, 32, endian: 'little', default: 0

    unsigned :desired_access, 32, endian: 'little'
    unsigned :file_attributes, 32, endian: 'little'
    unsigned :share_access, 32, endian: 'little'
    unsigned :disposition, 32, endian: 'little'
    unsigned :create_options, 32, endian: 'little'

    data_buffer :filename
    unsigned :create_contexts_offset, 32, endian: 'little'
    unsigned :create_contexts_length, 32, endian: 'little'

    rest :buffer

  end
end
