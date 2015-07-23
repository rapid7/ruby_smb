require 'ruby_smb/smb2/packet'

# [Section 2.2.10 SMB2 TREE_CONNECT Response](https://msdn.microsoft.com/en-us/library/cc246499.aspx)
class RubySMB::Smb2::Packet::TreeConnectResponse < RubySMB::Smb2::Packet::Response
  COMMAND = :TREE_CONNECT

  unsigned :struct_size, 16
  unsigned :share_type, 8
  unsigned :unused, 8
  unsigned :share_flags, 32
  unsigned :share_capabilities, 32
  unsigned :access_mask, 32
end
