module RubySMB
  module Smb1
    module Packet
      # This class represents an SMB_Data block structure for SMB1 packets.
      # [Section 2.2.3.3 Data Block](https://msdn.microsoft.com/en-us/library/ee441687.aspx)
      class SmbDataBlock < BitStruct
        unsigned :byte_count, 16
        rest :bytes

        def bytes=(value)
          raise ArgumentError, "value must be a binary string" unless value.kind_of? String
          self[2,(2 + value.length)] = value.force_encoding('binary')
          self.byte_count = self.bytes.size
        end
      end
    end
  end
end
