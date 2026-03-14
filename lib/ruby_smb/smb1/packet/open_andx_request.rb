module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_OPEN_ANDX Request Packet as defined in
      # [2.2.4.41.1 Request](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/0ab8c5c5-a8d1-4460-bab1-cdae4e18dab7)
      #
      # This is the LANMAN 1.0 file-open command, supported by all SMB1 servers
      # including Windows 95/98/ME which lack NT_CREATE_ANDX (0xA2).
      class OpenAndxRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_OPEN_ANDX

        # A SMB1 Parameter Block as defined by the {OpenAndxRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little

          and_x_block :andx_block
          uint16      :flags,             label: 'Flags'
          uint16      :access_mode,       label: 'Access Mode'
          uint16      :search_attributes, label: 'Search Attributes'
          uint16      :file_attributes,   label: 'File Attributes'
          uint32      :creation_time,     label: 'Creation Time'
          uint16      :open_mode,         label: 'Open Mode'
          uint32      :allocation_size,   label: 'Allocation Size'
          uint32      :timeout,           label: 'Timeout'
          uint32      :reserved,          label: 'Reserved'
        end

        # Represents the specific layout of the DataBlock for an {OpenAndxRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          stringz :file_name, label: 'File Name'
        end

        smb_header      :smb_header
        parameter_block :parameter_block
        data_block      :data_block
      end
    end
  end
end
