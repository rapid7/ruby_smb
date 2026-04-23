module RubySMB
  module SMB1
    module Packet
      module Trans2
        # The Trans2 Parameter Block for TRANS2_SET_FS_INFORMATION.
        # Observed on the wire (and required by Samba) as a 4-byte block
        # containing a placeholder file handle plus the information level.
        class SetFsInformationRequestTrans2Parameters < BinData::Record
          endian :little

          uint16 :fid,               label: 'File ID'
          uint16 :information_level, label: 'Information Level'

          # Returns the length of the Trans2Parameters struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The Trans2 Data Block for TRANS2_SET_FS_INFORMATION.
        #
        # The data layout depends on the Information Level being set, so the
        # block carries an opaque byte buffer that the caller fills in for
        # the target info level. SMB_SET_CIFS_UNIX_INFO (0x0200) for example
        # carries a QueryFsCifsUnixInfo-shaped record (major/minor/caps).
        class SetFsInformationRequestTrans2Data < BinData::Record
          string :buffer, read_length: -> { parent.buffer_read_length }

          # Returns the length of the Trans2Data struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type.
        class SetFsInformationRequestDataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
          uint8                                         :name,               label: 'Name', initial_value: 0x00
          string                                        :pad1,               length: -> { pad1_length }
          set_fs_information_request_trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
          string                                        :pad2,               length: -> { pad2_length }
          set_fs_information_request_trans2_data        :trans2_data,        label: 'Trans2 Data'
        end

        # A Trans2 SET_FS_INFORMATION Request Packet. The on-disk layout
        # described by [MS-CIFS] does not document the CIFS UNIX Extensions
        # info levels; their wire format is defined by the [SNIA CIFS UNIX
        # Extensions] draft and matched by Samba's {call_trans2setfsinfo}.
        class SetFsInformationRequest < RubySMB::GenericPacket
          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
          end

          smb_header                             :smb_header
          parameter_block                        :parameter_block
          set_fs_information_request_data_block  :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::SET_FS_INFORMATION
          end
        end
      end
    end
  end
end
