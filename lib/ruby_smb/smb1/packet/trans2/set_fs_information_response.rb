module RubySMB
  module SMB1
    module Packet
      module Trans2
        # The Trans2 Parameter Block for a TRANS2_SET_FS_INFORMATION response.
        # The field is intentionally empty — servers return only an NT status
        # in the SMB header to acknowledge the SET.
        class SetFsInformationResponseTrans2Parameters < BinData::Record
          def length
            do_num_bytes
          end
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type.
        class SetFsInformationResponseDataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
          uint8                                          :name,              label: 'Name', initial_value: 0x00
          string                                         :pad1,              length: -> { pad1_length }
          set_fs_information_response_trans2_parameters  :trans2_parameters, label: 'Trans2 Parameters'
        end

        # A Trans2 SET_FS_INFORMATION Response Packet.
        class SetFsInformationResponse < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Response::ParameterBlock
          end

          smb_header                              :smb_header
          parameter_block                         :parameter_block
          set_fs_information_response_data_block  :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::SET_FS_INFORMATION
            smb_header.flags.reply = 1
          end
        end
      end
    end
  end
end
