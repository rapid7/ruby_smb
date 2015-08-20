module RubySMB
  module SMB1
    module Packet

      # This class represents the Header of an SMB1 Packet.
      # [2.2.3.1 SMB Header Extensions](https://msdn.microsoft.com/en-us/library/cc246254.aspx)
      class SMBHeader < BinData::Record
        bit32   :protocol, :value => RubySMB::SMB1::SMB_PROTOCOL_ID
        bit8    :command
        bit32   :nt_status
        bit8    :flags
        bit16   :flags2
        bit16   :pid_high
        bit64   :security_features
        bit16   :reserved
        bit16   :tid
        bit16   :pid_low
        bit16   :uid
        bit16   :mid

        SMB_HEADER_BYTES = 0..31
      end
    end
  end
end