module RubySMB
  module SMB2
    module Packet
      # An SMB2 Set Info Request Packet as defined in
      # [2.2.39 SMB2 SET_INFO Request](https://msdn.microsoft.com/en-us/library/cc246560.aspx)
      class SetInfoRequest < RubySMB::GenericPacket
        endian :little

        smb2_header           :smb2_header
        uint16                :structure_size,         label: 'Structure Size',         initial_value: 33
        uint8                 :info_type,              label: 'Info Type',              initial_value: 0x01
        uint8                 :file_info_class,        label: 'File Info Class'
        uint32                :buffer_length,          label: 'Buffer Length'
        uint16                :buffer_offset,          label: 'Buffer Offset',          initial_value: 96
        uint16                :reserved,               label: 'Reserved',               initial_value: 0
        uint32                :additional_information, label: 'Additional Information', initial_value: 0
        smb2_fileid           :file_id,                label: 'File ID'
        string                :buffer,                 label: 'Buffer'

        def initialize_instance
          super
          smb2_header.command = RubySMB::SMB2::Commands::SET_INFO
        end
      end
    end
  end
end
