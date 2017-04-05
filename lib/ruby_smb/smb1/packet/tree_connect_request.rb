module RubySMB
  module SMB1
    module Packet

      # This class represents an SMB1 TreeConnect Request Packet as defined in
      # [2.2.4.7.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/cc246330.aspx)
      class TreeConnectRequest < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {TreeConnectRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          and_x_block          :andx_block
          tree_connect_flags   :flags
          uint16               :password_length, label: 'Password Length', initial_value: 0x00
        end

        class DataBlock < RubySMB::SMB1::DataBlock

        end

      end
    end
  end
end