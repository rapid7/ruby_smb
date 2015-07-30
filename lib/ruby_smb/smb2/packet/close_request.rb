require 'ruby_smb/smb2/packet'

# [Section 2.2.15 SMB2 CLOSE Request](https://msdn.microsoft.com/en-us/library/cc246523.aspx)
class RubySMB::SMB2::Packet::CloseRequest < RubySMB::SMB2::Packet::Request

  # A key in {RubySMB::SMB2::COMMANDS}
  COMMAND = :CLOSE

  unsigned :struct_size, 16, default: 24
  unsigned :flags, 16
  unsigned :reserved, 32
  string :file_id, 128
end
