module RubySMB
  module SMB1
    module Packet
      # This class represents an SMB_Parameters block structure for SMB1 packets.
      # [Section 2.2.3.2 Parameter Block](https://msdn.microsoft.com/en-us/library/ee442058.aspx)
      class SMBParameterBlock < BitStruct
        unsigned :word_count, 8, 'Size of data in Words'
        rest :words, 'Parameter Data'

        def words=(value)
          raise ArgumentError, "value must be a binary string" unless value.kind_of? String
          self[1,(1 + value.length)] = value.force_encoding('binary')
          self.word_count = (self.words.size/2)
        end
      end
    end
  end
end
