module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_OPEN_ANDX Response Packet as defined in
      # [MS-CIFS 2.2.4.41.2 Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/dbce00e7-68a1-41c6-982d-9483c902ad9b)
      class OpenAndxResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_OPEN_ANDX

        # A SMB1 Parameter Block as defined by the {OpenAndxResponse}.
        # Field names and layout follow MS-CIFS 2.2.4.41.2.
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little

          and_x_block         :andx_block
          uint16              :fid,             label: 'FID'
          smb_file_attributes :file_attributes, label: 'File Attributes'
          utime               :last_write_time, label: 'Last Write Time'
          uint32              :file_data_size,  label: 'File Data Size'
          uint16              :access_rights,   label: 'Access Rights'
          uint16              :resource_type,   label: 'Resource Type'
          smb_nmpipe_status   :nmpipe_status,   label: 'Named Pipe Status'
          uint16              :open_results,    label: 'Open Results'
          array               :reserved,        type: :uint16, initial_length: 3
        end

        class DataBlock < RubySMB::SMB1::DataBlock
        end

        smb_header      :smb_header
        parameter_block :parameter_block
        data_block      :data_block

        def initialize_instance
          super
          smb_header.flags.reply = 1
        end
      end
    end
  end
end
