module RubySMB
  module SMB1
    module Packet
      # Represents the ANDX Block in SMB1 ANDX Command Packets
      # [2.2.3.4 Batched Messages ("AndX" Messages)](https://msdn.microsoft.com/en-us/library/ee442210.aspx)
      class AndXBlock < BinData::Record
        endian  :little

        bit8  :andx_command,   :label => 'Next Command Code',  :value => RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
        bit8  :andx_reserved,  :label => 'AndX Reserved',      :value => 0x00
        bit16 :andx_offset,    :label => 'Andx Offset',        :value => 0x00

      end
    end
  end
end
