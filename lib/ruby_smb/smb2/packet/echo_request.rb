# [Section 2.2.28 SMB2 ECHO Request](https://msdn.microsoft.com/en-us/library/cc246540.aspx)
class RubySMB::Smb2::Packet::EchoRequest < RubySMB::Smb2::Packet::Request

  # A key in {RubySMB::Smb2::COMMANDS}
  COMMAND = :ECHO

  unsigned :structure_size, 16, default: 4
  unsigned :reserved, 16

end
