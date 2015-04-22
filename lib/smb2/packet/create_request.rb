require 'smb2/packet'

class Smb2::Packet

  # [Section 2.2.13 SMB2 CREATE Request](http://msdn.microsoft.com/en-us/library/cc246502.aspx)
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class CreateRequest < Smb2::Packet
    nest :header, RequestHeader
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

    unsigned :create_flags, 64

    unsigned :reserved, 64, default: 0

    # Wireshark calls this field 'Access Mask', which fits with the
    # documentation for possible values, but not the packet docs, which call
    # it 'Desired Access'
    #
    # @see https://msdn.microsoft.com/en-us/library/cc246503.aspx
    # @see https://msdn.microsoft.com/en-us/library/cc246802.aspx
    # @see https://msdn.microsoft.com/en-us/library/cc246801.aspx
    unsigned :desired_access, 32
    unsigned :file_attributes, 32
    unsigned :share_access, 32
    unsigned :disposition, 32
    unsigned :create_options, 32

    data_buffer :filename
    unsigned :create_contexts_offset, 32
    unsigned :create_contexts_length, 32

    rest :buffer

    # @return [Symbol] a key in {Smb2::COMMANDS}
    def self.command
      :CREATE
    end
  end
end
