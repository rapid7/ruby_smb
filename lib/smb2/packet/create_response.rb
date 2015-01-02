require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.14 SMB2 CREATE Response](http://msdn.microsoft.com/en-us/library/cc246512.aspx)
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class CreateResponse < Smb2::Packet
    nest :header, ResponseHeader
    # "The server MUST set this field to 89, indicating the size of the
    # request structure, not including the header. The client MUST set it to
    # this value regardless of how long Buffer[] actually is in the request
    # being sent."
    unsigned :struct_size, 16, endian: 'little', default: 89

    unsigned :oplock, 8

    # "If the server implements the SMB 3.x dialect family, this field MUST be
    # constructed using the following value. Otherwise, this field MUST NOT be
    # used and MUST be reserved."
    unsigned :flags, 8, default: 0

    unsigned :create_action, 32, endian: 'little'
    unsigned :creation_time, 64, endian: 'little'
    unsigned :last_action_time, 64, endian: 'little'
    unsigned :last_write_time, 64, endian: 'little'
    unsigned :change_time, 64, endian: 'little'
    unsigned :allocation_size, 64, endian: 'little'
    unsigned :end_of_file, 64, endian: 'little'
    unsigned :file_attributes, 32, endian: 'little'
    unsigned :reserved2, 32, endian: 'little'

    string :file_id, 128

    unsigned :create_contexts_offset, 32, endian: 'little'
    unsigned :create_contexts_length, 32, endian: 'little'

  end
end
