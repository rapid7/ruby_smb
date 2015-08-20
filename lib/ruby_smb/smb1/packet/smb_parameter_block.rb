module RubySMB
  module SMB1
    module Packet
      # This class represents an SMB_Parameters block structure for SMB1 packets.
      # [Section 2.2.3.2 Parameter Block](https://msdn.microsoft.com/en-us/library/ee442058.aspx)
      class SMBParameterBlock < BinData::Record
        endian  :little
        uint8   :word_count,  :value => lambda { (words.force_encoding('binary').length / 2.0).ceil }
        string  :words,       :read_length => lambda { word_count * 2 }, :assert => lambda { words.value.class == String }

        SMB_PARAMETER_BLOCK_OFFSET = 32
        SMB_PARAMETER_WORD_COUNT = 1
      end
    end
  end
end