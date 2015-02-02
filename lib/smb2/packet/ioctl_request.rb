require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.31 SMB2 IOCTL Request](https://msdn.microsoft.com/en-us/library/cc246545.aspx)
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class IoctlRequest < Smb2::Packet
    nest :header, RequestHeader

    # > The client MUST set this field to 57, indicating the size of the
    #   request structure, not including the header. The client MUST set it to
    #   this value regardless of how long Buffer[] actually is in the request
    #   being sent."
    unsigned :struct_size, 16, default: 57

    unsigned :reserved, 16, default: 0

    # > The control code of the FSCTL/IOCTL method. The values are listed in
    #   subsequent sections, and in [MS-FSCC] section 2.3. The following values
    #   indicate SMB2-specific processing as specified in sections 3.2.4.20 and
    #   3.3.5.15.
    unsigned :ctl_code, 32

    # > An SMB2_FILEID identifier of the file on which to perform the command
    string :file_id, 128

    data_buffer :input_data, 32, offset_bitlength: 32

    # > The maximum number of bytes that the server can return for the input
    #   data in the {IoctlResponse SMB2 IOCTL Response}
    unsigned :max_input_response, 32, default: 0

    # This, along with {#output_data_length} are kind of a {data_buffer}, but there
    # should never be any data associated with them in a request packet.
    # > The client SHOULD set this to 0.
    unsigned :output_data_offset, 32, default: 0

    # This, along with {#output_data_offset} are kind of a {data_buffer}, but there
    # should never be any data associated with them in a request packet.
    # > The client MUST set this to 0.
    unsigned :output_data_length, 32, default: 0

    # > The maximum number of bytes that the server can return for the output
    #   data in the {IoctlResponse SMB2 IOCTL Response}
    unsigned :max_output_response, 32

    # A Flags field indicating how to process the operation. This field MUST
    # be constructed using one of the following values.
    #
    # | Value | Meaning |
    # | ----- | ------- |
    # | 0x00000000 | If Flags is set to this value, the request is an IOCTL request. |
    # | SMB2_0_IOCTL_IS_FSCTL 0x00000001 | If Flags is set to this value, the request is an FSCTL request. |
    unsigned :flags, 32

    # > This field MUST NOT be used and MUST be reserved. The client MUST set
    #   this field to 0, and the server MUST ignore it on receipt
    unsigned :reserved2, 32


    rest :buffer

    FLAGS = {
      SMB2_0_IOCTL_IS_IOCTL: 0,
      SMB2_0_IOCTL_IS_FSCTL: 1
    }.freeze

  end
end
