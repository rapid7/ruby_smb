module RubySMB
  module SMB1
    module Packet
      class SMBHeader < BinData::Record
        endian  :little

        # SMBHeader
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
      end
    end
  end
end
