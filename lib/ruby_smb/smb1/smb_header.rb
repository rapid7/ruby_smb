module RubySMB
  module SMB1
    # Represents the Header of an SMB1 packet as defined in
    # [2.2.3.1 SMB Header Extensions](https://msdn.microsoft.com/en-us/library/cc246254.aspx)
    class SMBHeader < BinData::Record
      endian  :little
      bit32         :protocol,                    :label => 'Protocol ID Field',          :value => RubySMB::SMB1::SMB_PROTOCOL_ID
      bit8          :command,                     :label => 'SMB Command ID'
      nt_status         :nt_status,                   :label => 'NTStatus Code'
      header_flags  :flags
      header_flags2 :flags2
      bit16         :pid_high,                    :label => 'PID High Bytes'
      bit64         :security_features,           :label => 'Security Features'
      bit16         :reserved,                    :label => 'Reserved'
      bit16         :tid,                         :label => 'Tree ID'
      bit16         :pid_low,                     :label => 'PID Low Bytes'
      bit16         :uid,                         :label => 'User ID'
      bit16         :mid,                         :label => 'Multiplex ID'
    end
  end
end
