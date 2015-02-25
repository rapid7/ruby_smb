require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.9 SMB2 TREE_CONNECT Request](https://msdn.microsoft.com/en-us/library/cc246567.aspx)
  class TreeConnectRequest < Smb2::Packet
    nest :header, RequestHeader
    unsigned :struct_size, 16
    # These two bytes are used in the response, but just padding in the
    # request
    unsigned :unused, 16
    data_buffer :tree

    rest :buffer

  end
end
