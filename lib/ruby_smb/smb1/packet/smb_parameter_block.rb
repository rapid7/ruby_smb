module RubySMB
  module Smb1
    module Packet
      # This class represents an SMB_Parameters block structure for SMB1 packets.
      # [Section 2.2.3.2 Parameter Block](https://msdn.microsoft.com/en-us/library/ee442058.aspx)
      class SmbParameterBlock < BitStruct
        unsigned :word_count, 8
        rest :words

        def words=(value)
          self[1,(1 + value.length)] = value.force_encoding('binary')
          self.word_count = (self.words.size/2)
        end
      end
    end
  end
end
