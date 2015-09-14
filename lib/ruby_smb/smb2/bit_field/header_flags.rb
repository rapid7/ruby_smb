module RubySMB
  module SMB2
    module BitField
      # The Flags bit-field for an SMB2 Header as defined in
      # [2.2.1.2 SMB2 Packet Header - SYNC](https://msdn.microsoft.com/en-us/library/cc246529.aspx)
      class HeaderFlags < BinData::Record
        endian  :little
        bit2    :reserved1,           :label => 'Reserved',           :value => 0
        bit1    :replay_operation,    :label => 'Replay Operation'
        bit1    :dfs_operation,       :label => 'DFS Operation'
        resume_byte_alignment
        # byte border
        uint16  :reserved2,           :label => 'Reserved',           :value => 0
        # byte border
        bit4    :reserved3,           :label => 'Reserved',           :value => 0
        bit1    :signed,              :label => 'Packet Signed'
        bit1    :related_operations,  :label => 'Chained Request'
        bit1    :async_command,       :label => 'ASYNC Command',      :value => 0
        bit1    :reply,               :label => 'Response'
      end
    end
  end
end
