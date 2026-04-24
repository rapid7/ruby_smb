module RubySMB
  module SMB1
    module Packet
      module Trans2
        # The Trans2 Parameter Block for a TRANS2_SET_FS_INFORMATION response.
        # The field is intentionally empty — servers return only an NT status
        # in the SMB header to acknowledge the SET.
        #
        # Parent subcommand:
        # [MS-CIFS 2.2.6.5 TRANS2_SET_FS_INFORMATION (0x0004)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/ac4b00db-6015-416a-89a1-bf5da2503bc3)
        # ("reserved but not implemented"). Response shape observed in the
        # CIFS UNIX Extensions implementation in
        # [source3/smbd/smb1_trans2.c](https://github.com/samba-team/samba/blob/master/source3/smbd/smb1_trans2.c).
        class SetFsInformationResponseTrans2Parameters < BinData::Record
          def length
            do_num_bytes
          end
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type.
        # Parent subcommand:
        # [MS-CIFS 2.2.6.5 TRANS2_SET_FS_INFORMATION (0x0004)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/ac4b00db-6015-416a-89a1-bf5da2503bc3)
        # ("reserved but not implemented"); actual shape used by the CIFS
        # UNIX Extensions implementation in
        # [source3/smbd/smb1_trans2.c](https://github.com/samba-team/samba/blob/master/source3/smbd/smb1_trans2.c).
        class SetFsInformationResponseDataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
          uint8                                          :name,              label: 'Name', initial_value: 0x00
          string                                         :pad1,              length: -> { pad1_length }
          set_fs_information_response_trans2_parameters  :trans2_parameters, label: 'Trans2 Parameters'
        end

        # A Trans2 SET_FS_INFORMATION Response Packet. Parent subcommand:
        # [MS-CIFS 2.2.6.5 TRANS2_SET_FS_INFORMATION (0x0004)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/ac4b00db-6015-416a-89a1-bf5da2503bc3)
        # ("reserved but not implemented"). Response shape is defined by the
        # CIFS UNIX Extensions implementation in
        # [source3/smbd/smb1_trans2.c](https://github.com/samba-team/samba/blob/master/source3/smbd/smb1_trans2.c).
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
