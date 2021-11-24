module RubySMB
  module SMB2
    module Packet
      # An SMB2 Query Info Request Packet as defined in
      # [2.2.37 SMB2 QUERY_INFO Request](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d623b2f7-a5cd-4639-8cc9-71fa7d9f9ba9)
      class QueryInfoRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::QUERY_INFO

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size,          label: 'Structure Size', initial_value: 41
        uint8        :info_type,               label: 'Information Type'
        uint8        :file_information_class,  label: 'File Information Class'
        uint32       :output_buffer_length,    label: 'Output Buffer Length'
        uint16       :input_buffer_offset,     label: 'Input Buffer Offset'
        uint16       :reserved,                label: 'Reserved Space'
        uint32       :input_buffer_length,     label: 'Input Buffer Length'
        struct       :additional_information do
          bit1       :reserved
          bit1       :scope_security_information,     label: 'Scope Security Information'
          bit1       :attribute_security_information, label: 'Attribute Security Information'
          bit1       :label_security_information,     label: 'Label Security Information'
          bit1       :sacl_security_information,      label: 'SACL Security Information'
          bit1       :dacl_security_information,      label: 'DACL Security Information'
          bit1       :group_security_information,     label: 'Group Security Information'
          bit1       :owner_security_information,     label: 'Owner Security Information'
          skip       length: 3
        end
        struct       :flags do
          bit5       :reserved
          bit1       :sl_index_specified,      label: 'Index Specified'
          bit1       :sl_return_single_entry,  label: 'Return Single Entry'
          bit1       :sl_restart_scan,         label: 'Restart Scan'
          skip       length: 3
        end
        smb2_fileid  :file_id,                 label: 'File ID'
        string       :buffer,                  label: 'Buffer'
      end
    end
  end
end
