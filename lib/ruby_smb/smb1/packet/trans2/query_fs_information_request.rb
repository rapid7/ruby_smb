module RubySMB
  module SMB1
    module Packet
      module Trans2
        # The Trans2 Parameter Block for this particular Subcommand
        class QueryFsInformationRequestTrans2Parameters < BinData::Record
          endian :little

          uint16 :information_level, label: 'Information Level'

          # Returns the length of the Trans2Parameters struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type.
        class QueryFsInformationRequestDataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
          uint8                                           :name,               label: 'Name', initial_value: 0x00
          string                                          :pad1,               length: -> { pad1_length }
          query_fs_information_request_trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
          # trans2_data: No data is sent by this message.
        end

        # A Trans2 QUERY_FS_INFORMATION Request Packet as defined in
        # [2.2.6.4.1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/cfa23a11-0e80-43bd-bbd4-e9cfb99b5dce)
        class QueryFsInformationRequest < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
          end

          smb_header                               :smb_header
          parameter_block                          :parameter_block
          query_fs_information_request_data_block  :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::QUERY_FS_INFORMATION
          end
        end
      end
    end
  end
end
