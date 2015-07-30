# [Section 2.2.29 SMB2 ECHO Response](https://msdn.microsoft.com/en-us/library/cc246541.aspx)
class RubySMB::SMB2::Packet::EchoResponse < RubySMB::SMB2::Packet::Response
  unsigned :structure_size, 16, default: 4
  unsigned :reserved, 16
end
