require 'smb2/packet'

class Smb2::Packet
  # [Section 2.2.31 SMB2 IOCTL Response]()
  #
  # [Example 4.4 Executing an Operation on a Named Pipe](http://msdn.microsoft.com/en-us/library/cc246794.aspx)
  class IoctlResponse < Smb2::Packet

  end
end
