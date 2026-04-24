module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_OPEN_ANDX Response Packet as defined in
      # [MS-CIFS 2.2.4.41.2 Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/dbce00e7-68a1-41c6-982d-9483c902ad9b)
      class OpenAndxResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_OPEN_ANDX

        # A SMB1 Parameter Block as defined by the {OpenAndxResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little

          and_x_block :andx_block
          uint16      :fid,              label: 'FID'
          smb_file_attributes  :file_attributes,  label: 'File Attributes'
          uint32      :last_write_time,  label: 'Last Write Time'
          uint32      :data_size,        label: 'File Data Size'
          uint16      :granted_access,   label: 'Granted Access'
          uint16      :file_type,        label: 'File Type'
          uint16      :device_state,     label: 'Device State'
          uint16      :action,           label: 'Action Taken'
          uint32      :server_fid,       label: 'Server FID'
          uint16      :reserved,         label: 'Reserved'
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
