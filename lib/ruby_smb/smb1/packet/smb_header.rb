module RubySMB
  module SMB1
    module Packet

      # This class represents the Header of an SMB1 Packet.
      # [2.2.3.1 SMB Header Extensions](https://msdn.microsoft.com/en-us/library/cc246254.aspx)
      class SMBHeader < BitStruct
        unsigned :protocol,          32, 'Protocol Implementation', default: RubySMB::SMB1::SMB_PROTOCOL_ID
        unsigned :command,            8, 'SMB Command Code'
        unsigned :nt_status,         32, 'NTStatus Error Code'
        unsigned :flags,              8, 'Flags'
        unsigned :flags2,            16, 'Flags2'
        unsigned :pid_high,          16, 'Process ID High Bytes'
        unsigned :security_features, 64, 'Security Features'
        unsigned :reserved,          16, 'Reserved Field'
        unsigned :tid,               16, 'Tree ID'
        unsigned :pid_low,           16, 'Process ID Low Bytes'
        unsigned :uid,               16, 'User ID'
        unsigned :mid,               16, 'Multiplex ID'

      end
    end
  end
end
