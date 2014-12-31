require 'smb2/packet'

class Smb2::Packet
  class TreeConnectResponse < Smb2::Packet
    nest :header, RequestHeader
    unsigned :struct_size, 16, endian: 'little'
    unsigned :share_type, 8
    unsigned :unused, 8
    unsigned :share_flags, 32, endian: 'little'
    unsigned :share_capabilities, 32, endian: 'little'
    unsigned :access_mask, 32, endian: 'little'
  end
end

