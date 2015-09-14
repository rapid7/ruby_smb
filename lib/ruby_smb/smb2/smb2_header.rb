module RubySMB
  module SMB2
    # Represents the Header of an SMB2 packet as defined in
    # [2.2.1.2 SMB2 Packet Header - SYNC](https://msdn.microsoft.com/en-us/library/cc246529.aspx)
    class SMB2Header < BinData::Record
      endian      :little
      bit32       :protocol,          :label => 'Protocol ID Field',      :value => RubySMB::SMB1::SMB_PROTOCOL_ID
      uint16      :structure_size,    :label => 'Header Structure Size',  :value => 64
      uint16      :credit_charge,     :label => 'Credit Charge',          :value => 0
      nt_status   :status,            :label => 'NT Status',              :value => 0
      uint16      :command,           :label => 'Command'
      uint16      :credits,           :label => 'Credit Request/Response'

    end
  end
end