module RubySMB
  module Smb1
    module Packet

      # This class represents the Header of an SMB1 Packet.
      # [2.2.3.1 SMB Header Extensions](https://msdn.microsoft.com/en-us/library/cc246254.aspx)
      class SmbHeader < BitStruct
        unsigned :protocol,          32
        unsigned :command,            8
        unsigned :nt_status,         32
        unsigned :flags,              8
        unsigned :flags2,            16
        unsigned :pid_high,          16
        unsigned :security_features, 64
        unsigned :reserved,          16
        unsigned :tid,               16
        unsigned :pid_low,           16
        unsigned :uid,               16
        unsigned :mid,               16

      end
    end
  end
end
