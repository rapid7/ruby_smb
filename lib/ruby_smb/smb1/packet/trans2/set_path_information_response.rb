module RubySMB
  module SMB1
    module Packet
      module Trans2
        # The Trans2 Parameter Block for a SET_PATH_INFORMATION response as
        # defined in
        # [MS-CIFS 2.2.6.7.2 Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/cf1cd579-9687-465d-9274-08ebb5944cd3).
        class SetPathInformationResponseTrans2Parameters < BinData::Record
          endian :little

          uint16 :ea_error_offset, label: 'Extended Attribute Error Offset'

          # Returns the length of the Trans2Parameters struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type. See
        # [MS-CIFS 2.2.6.7.2 Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/cf1cd579-9687-465d-9274-08ebb5944cd3).
        class SetPathInformationResponseDataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
          string                                           :pad1,               length: -> { pad1_length }
          set_path_information_response_trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
          # trans2_data: No data is sent by this message.
        end

        # A Trans2 SET_PATH_INFORMATION Response Packet as defined in
        # [MS-CIFS 2.2.6.7.2 Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/cf1cd579-9687-465d-9274-08ebb5944cd3).
        # See also the subcommand overview at
        # [MS-CIFS 2.2.6.7 TRANS2_SET_PATH_INFORMATION (0x0006)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/a23483d9-6543-4aaa-a996-e7c9506f8b94).
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
