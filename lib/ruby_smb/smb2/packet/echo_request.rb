# [Section 2.2.28 SMB2 ECHO Request](https://msdn.microsoft.com/en-us/library/cc246540.aspx)
class RubySMB::SMB2::Packet::EchoRequest < RubySMB::SMB2::Packet::Request

  # A key in {RubySMB::SMB2::COMMANDS}
  COMMAND = :ECHO

  unsigned :structure_size, 16, default: 4
  unsigned :reserved, 16

end
