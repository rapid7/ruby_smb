module RubySMB
  module SMB1
    module Packet
      # This class represents an SMB_Data block structure for SMB1 packets.
      # [Section 2.2.3.3 Data Block](https://msdn.microsoft.com/en-us/library/ee441687.aspx)
      class SMBDataBlock < BinData::Record
        endian  :little
        uint16  :byte_count,  :value => lambda { bytes.length }
        rest    :bytes,       :assert => lambda { bytes.value.class == String }

        SMB_DATA_BYTE_SIZE = 2
      end
    end
  end
end