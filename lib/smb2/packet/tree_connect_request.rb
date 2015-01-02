require 'smb2/packet'

class Smb2::Packet
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
