require 'smb2/packet'

class Smb2::Packet

  # [Section 2.2.15 SMB2 CLOSE Request](https://msdn.microsoft.com/en-us/library/cc246523.aspx)
  class CloseRequest < Smb2::Packet
    nest :header, RequestHeader
    unsigned :struct_size, 16, default: 24
    unsigned :flags, 16
    unsigned :reserved, 32
    string :file_id, 128

    def self.command
      :CLOSE
    end
  end

end

