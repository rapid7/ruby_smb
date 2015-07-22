require 'smb2/packet'

# [Section 2.2.15 SMB2 CLOSE Request](https://msdn.microsoft.com/en-us/library/cc246523.aspx)
class Smb2::Packet::CloseRequest < Smb2::Packet::Request

  # A key in {Smb2::COMMANDS}
  COMMAND = :CLOSE

  unsigned :struct_size, 16, default: 24
  unsigned :flags, 16
  unsigned :reserved, 32
  string :file_id, 128
end
