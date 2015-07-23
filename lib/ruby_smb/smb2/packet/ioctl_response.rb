require 'ruby_smb/smb2/packet'

# [Section 2.2.31 SMB2 IOCTL Response]()
#
# [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
class RubySMB::Smb2::Packet::IoctlResponse < RubySMB::Smb2::Packet::Response
  COMMAND = :IOCTL

end
