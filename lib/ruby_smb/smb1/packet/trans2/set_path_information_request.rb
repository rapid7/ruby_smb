module RubySMB
  module SMB1
    module Packet
      module Trans2
        # The Trans2 Parameter Block for a SET_PATH_INFORMATION request as
        # defined in
        # [MS-CIFS 2.2.6.7.1 Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/2ca0642a-1cd4-4e72-a16f-9e804a218262).
        class SetPathInformationRequestTrans2Parameters < BinData::Record
          endian :little

          uint16     :information_level, label: 'Information Level'
          uint32     :reserved,          label: 'Reserved'
          choice     :filename, copy_on_change: true, selection: -> { parent.parent.smb_header.flags2.unicode } do
            stringz16 1, label: 'FileName'
            stringz   0, label: 'FileName'
          end

          # Returns the length of the Trans2Parameters struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The Trans2 Data Block for a SET_PATH_INFORMATION request as defined
        # in
        # [MS-CIFS 2.2.6.7.1 Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/2ca0642a-1cd4-4e72-a16f-9e804a218262).
        #
        # The data layout depends on the Information Level being set, so the
        # block carries an opaque byte buffer that the caller fills in for the
        # target info level. SMB_SET_FILE_UNIX_LINK (0x0201) for example
        # carries the symlink target as a null-terminated string.
        class SetPathInformationRequestTrans2Data < BinData::Record
          string :buffer, read_length: -> { parent.buffer_read_length }

          # Returns the length of the Trans2Data struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type. See
        # [MS-CIFS 2.2.6.7.1 Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/2ca0642a-1cd4-4e72-a16f-9e804a218262).
        class SetPathInformationRequestDataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
          uint8                                           :name,               label: 'Name', initial_value: 0x00
          string                                          :pad1,               length: -> { pad1_length }
          set_path_information_request_trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
          string                                          :pad2,               length: -> { pad2_length }
          set_path_information_request_trans2_data        :trans2_data,        label: 'Trans2 Data'
        end

        # A Trans2 SET_PATH_INFORMATION Request Packet as defined in
        # [MS-CIFS 2.2.6.7.1 Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/2ca0642a-1cd4-4e72-a16f-9e804a218262).
        # See also the subcommand overview at
        # [MS-CIFS 2.2.6.7 TRANS2_SET_PATH_INFORMATION (0x0006)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/a23483d9-6543-4aaa-a996-e7c9506f8b94).
        class SetPathInformationRequest < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
          end

          smb_header                               :smb_header
          parameter_block                          :parameter_block
          set_path_information_request_data_block  :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::SET_PATH_INFORMATION
          end
        end
      end
    end
  end
end
