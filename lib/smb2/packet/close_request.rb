require 'smb2/packet'

class Smb2::Packet

  class CloseRequest < Smb2::Packet
    nest :header, RequestHeader
    unsigned :struct_size, 16, default: 24
    unsigned :flags, 16
    unsigned :reserved, 32
    string :file_id, 128
  end

end

