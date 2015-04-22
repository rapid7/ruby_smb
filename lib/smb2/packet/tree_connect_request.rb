require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.9 SMB2 TREE_CONNECT Request](https://msdn.microsoft.com/en-us/library/cc246567.aspx)
  class TreeConnectRequest < Smb2::Packet
    nest :header, RequestHeader
    # "The client MUST set this field to 9, indicating the size of the request
    # structure, not including the header. The client MUST set it to this
    # value regardless of how long Buffer[] actually is in the request being
    # sent."
    unsigned :struct_size, 16, default: 9
    # These two bytes are used in the response, but just padding in the
    # request
    unsigned :reserved, 16, default: 0
    data_buffer :tree

    rest :buffer

    # @return [Symbol] a key in {Smb2::COMMANDS}
    def self.command
      :TREE_CONNECT
    end

  end
end
