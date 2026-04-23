module RubySMB
  module SMB1
    module Packet
      module Trans2
        # The Trans2 Parameter Block for this particular Subcommand
        class SetPathInformationResponseTrans2Parameters < BinData::Record
          endian :little

          uint16 :ea_error_offset, label: 'Extended Attribute Error Offset'

          # Returns the length of the Trans2Parameters struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type.
        class SetPathInformationResponseDataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
          string                                           :pad1,               length: -> { pad1_length }
          set_path_information_response_trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
          # trans2_data: No data is sent by this message.
        end

        # A Trans2 SET_PATH_INFORMATION Response Packet as defined in
        # [2.2.6.8.2 Response](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/4b7cc4ce-e3f4-4c47-b9ff-8f6c4cb5e05d)
        class SetPathInformationResponse < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Response::ParameterBlock
          end

          smb_header                                :smb_header
          parameter_block                           :parameter_block
          set_path_information_response_data_block  :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::SET_PATH_INFORMATION
            smb_header.flags.reply = 1
          end
        end
      end
    end
  end
end
