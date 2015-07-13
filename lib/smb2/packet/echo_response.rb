require 'smb2/packet'

class Smb2::Packet

  # [Section 2.2.29 SMB2 ECHO Response](https://msdn.microsoft.com/en-us/library/cc246541.aspx)
  class EchoResponse < Smb2::Packet
    nest :header, ResponseHeader

    unsigned :structure_size, 16, default: 4
    unsigned :reserved, 16
  end
end
