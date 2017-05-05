module RubySMB
  module SMB1
    module Packet
      module Trans2

        # A Trans2 OPEN2 Request Packet as defined in
        # [2.2.6.1.1 Request](https://msdn.microsoft.com/en-us/library/ee441733.aspx)
        class Open2Request < BinData::Record

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
          end

          class Trans2Parameters < BinData::Record
            endian :little
            open2_flags         :flags,           label: 'Flags'
            open2_access_mode   :access_mode,     label: 'AccessMode'
            uint16              :reserved,        label: 'Reserved Space'
            smb_file_attributes :file_attributes, label: 'File Attributes'
            utime               :creation_time,   label: 'Creation Time'
            open2_open_mode     :open_mode,       label: 'Open Mode'
            uint32              :allocation_size, label: 'Allocation Size'
            array               :reserved2,        initial_length: 5 do
              uint16 value: 0x0000
            end
            stringz             :filename,        label: 'Filename'

          end

          class Trans2Data < BinData::Record
            smb_fea_list  :extended_attribute_list, label: 'Extended Attribute List'
          end

          class DataBlock < RubySMB::SMB1::DataBlock
            uint8              :name,               label: 'Name',              initial_value: 0x00
            string             :pad1,               length: lambda { pad1_length }
            trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
            string             :pad2,               length: lambda { pad2_length }
            trans2_data        :trans2_data,        label: 'Trans2 Data'

            private

            # Determines the correct length for the padding in front of
            # #trans2_parameters. It should always force a 4-byte alignment.
            def pad1_length
              offset = (name.abs_offset + 1) % 4
              (4 - offset) % 4
            end

            # Determines the correct length for the padding in front of
            # #trans2_data. It should always force a 4-byte alignment.
            def pad2_length
              offset = (trans2_parameters.abs_offset + trans2_parameters.do_num_bytes) % 4
              (4 - offset) % 4
            end
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block


          def initialize_instance
            super
            smb_header.command = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::OPEN2
          end
        end
      end
    end
  end
end
