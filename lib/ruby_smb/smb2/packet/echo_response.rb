# [Section 2.2.29 SMB2 ECHO Response](https://msdn.microsoft.com/en-us/library/cc246541.aspx)
class RubySMB::Smb2::Packet::EchoResponse < RubySMB::Smb2::Packet::Response
  unsigned :structure_size, 16, default: 4
  unsigned :reserved, 16
end
