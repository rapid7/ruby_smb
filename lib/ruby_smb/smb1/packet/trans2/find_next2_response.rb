module RubySMB
  module SMB1
    module Packet
      module Trans2

        # This class represents an SMB1 Trans2 FIND_NEXT2 Response Packet as defined in
        # [2.2.6.3.2 Response](https://msdn.microsoft.com/en-us/library/ee441871.aspx)
        class FindNext2Response < RubySMB::GenericPacket

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Response::ParameterBlock
          end

          class Trans2Parameters < BinData::Record
            endian  :little

            uint16  :search_count,      label: 'Search Count'
            uint16  :eos,               label: 'End of Search'
            uint16  :ea_error_offset,   label: 'Offset to EA Error'
            uint16  :last_name_offset,  label: 'Last Name Offset'

            # Returns the length of the Trans2Parameters struct
            # in number of bytes
            def length
              self.do_num_bytes
            end
          end

          class Trans2Data < BinData::Record
            rest  :buffer,  label: 'Results Buffer'

            # Returns the length of the Trans2Data struct
            # in number of bytes
            def length
              self.do_num_bytes
            end
          end

          class DataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
            uint8              :name,               label: 'Name',              initial_value: 0x00
            string             :pad1,               length: lambda { pad1_length }
            trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
            string             :pad2,               length: lambda { pad2_length }
            trans2_data        :trans2_data,        label: 'Trans2 Data',           length: 0
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

          def initialize_instance
            super
            smb_header.command     = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::FIND_NEXT2
            smb_header.flags.reply = 1
          end

          # Returns the File Information in an array of appropriate
          # structs for the given FileInformationClass. Pulled out of
          # the string buffer.
          #
          # @param klass [Class] the FileInformationClass class to read the data as
          # @return [array<BinData::Record>] An array of structs holding the requested information
          def results(klass)
            information_classes = []
            blob = self.data_block.trans2_data.buffer.to_binary_s.dup
            while blob.length > 0
              length = blob[0,4].unpack('V').first

              if length.zero?
                data = blob.slice!(0,blob.length)
              else
                data = blob.slice!(0,length)
              end

              information_classes << klass.read(data)
            end
            information_classes
          end


        end
      end
    end
  end
end