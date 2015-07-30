module RubySMB
  module Smb1
    module Packet

      # This class represents an AndX message block that allows the chaining
      # of multiple SMB Commands in a single packet.
      # [2.2.3.4 Batched Messages ("AndX" Messages)](https://msdn.microsoft.com/en-us/library/ee442210.aspx)
      class AndXBlock < BitStruct
        unsigned :andx_command,      8, 'Next Command Code', default: RubySMB::Smb1::COMMANDS[:SMB_COM_NO_ANDX_COMMAND]
        unsigned :andx_reserved,     8, 'AndX Reserved Field', default: 0
        unsigned :andx_offset,      16, 'Offset to the next AndX Command', default: 0
      end
    end
  end
end
