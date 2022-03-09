module RubySMB
  module SMB1
    module Packet
      module Trans2
        # The Trans2 Parameter Block for this particular Subcommand
        class QueryFileInformationRequestTrans2Parameters < BinData::Record
          endian :little

          uint16 :fid,               label: 'FID'
          uint16 :information_level, label: 'Information Level'

          # Returns the length of the Trans2Parameters struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The Trans2 Data Block for this particular Subcommand
        class QueryFileInformationRequestTrans2Data < BinData::Record
          smb_gea_list :extended_attribute_list, label: 'Get Extended Attribute List',
            onlyif: -> { parent.trans2_parameters.information_level == FindInformationLevel::SMB_INFO_QUERY_EAS_FROM_LIST}

          # Returns the length of the Trans2Data struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type.
        class QueryFileInformationRequestDataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
          uint8                                             :name,               label: 'Name', initial_value: 0x00
          string                                            :pad1,               length: -> { pad1_length }
          query_file_information_request_trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
          string                                            :pad2,               length: -> { pad2_length }
          query_file_information_request_trans2_data        :trans2_data,        label: 'Trans2 Data'
        end

        # A Trans2 QUERY_FILE_INFORMATION Request Packet as defined in
        # [2.2.6.8.1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/357bf60d-f30a-457e-9787-9f78322b92d3)
        class QueryFileInformationRequest < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
          end

          smb_header                                 :smb_header
          parameter_block                            :parameter_block
          query_file_information_request_data_block  :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::QUERY_FILE_INFORMATION
          end
        end
      end
    end
  end
end
