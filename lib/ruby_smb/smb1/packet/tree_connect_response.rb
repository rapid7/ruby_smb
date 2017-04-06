module RubySMB
  module SMB1
    module Packet

      # A SMB1 TreeConnect Response Packet as defined in
      # [2.2.4.7.2 Server Response Extensions](https://msdn.microsoft.com/en-us/library/cc246331.aspx)
      class TreeConnectResponse < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {SessionSetupResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          and_x_block         :andx_block
          optional_support    :optional_support
        end

        # Represents the specific layout of the DataBlock for a {SessionSetupResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock

        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP
          smb_header.flags.reply = 1
        end


      end
    end
  end
end
