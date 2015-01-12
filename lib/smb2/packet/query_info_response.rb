require 'smb2/packet'

class Smb2::Packet

  class QueryInfoResponse < Smb2::Packet
    nest :header, ResponseHeader
    unsigned :struct_size, 16, default: 9

    data_buffer :output_buffer, 32

    rest :buffer
  end

end


