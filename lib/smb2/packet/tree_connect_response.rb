require 'smb2/packet'

# [Section 2.2.10 SMB2 TREE_CONNECT Response](https://msdn.microsoft.com/en-us/library/cc246499.aspx)
class Smb2::Packet::TreeConnectResponse < Smb2::Packet::Response
  unsigned :struct_size, 16
  unsigned :share_type, 8
  unsigned :unused, 8
  unsigned :share_flags, 32
  unsigned :share_capabilities, 32
  unsigned :access_mask, 32
end
