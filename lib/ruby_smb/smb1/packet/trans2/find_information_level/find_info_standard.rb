module RubySMB
  module SMB1
    module Packet
      module Trans2
        module FindInformationLevel
          # SMB_INFO_STANDARD find result entry, as defined in
          # [MS-CIFS 2.2.8.1.1 SMB_INFO_STANDARD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/b7cc0966-f87d-41a6-aa1a-48526a9cc729).
          # Used by TRANS2_FIND_FIRST2/FIND_NEXT2 on legacy servers
          # (e.g. Windows 95/98/ME) that don't support NT LANMAN info levels.
          #
          # Unlike NT info levels, these entries have no next_offset field;
          # they are packed sequentially with a variable-length filename.
          # The optional leading ResumeKey (4 bytes) is only present when the
          # SMB_FIND_RETURN_RESUME_KEYS flag is set in the request; this
          # implementation does not set that flag and so omits the field.
          class FindInfoStandard < BinData::Record
            CLASS_LEVEL = FindInformationLevel::SMB_INFO_STANDARD

            endian :little

            uint16  :creation_date,    label: 'Creation Date (SMB_DATE)'
            uint16  :creation_time,    label: 'Creation Time (SMB_TIME)'
            uint16  :last_access_date, label: 'Last Access Date (SMB_DATE)'
            uint16  :last_access_time, label: 'Last Access Time (SMB_TIME)'
            uint16  :last_write_date,  label: 'Last Write Date (SMB_DATE)'
            uint16  :last_write_time,  label: 'Last Write Time (SMB_TIME)'
            uint32  :data_size,        label: 'File Data Size'
            uint32  :allocation_size,  label: 'Allocation Size'
            uint16  :file_attributes,  label: 'File Attributes'
            uint8   :file_name_length, label: 'File Name Length',
                    initial_value: -> { file_name.to_s.bytesize }
            string  :file_name,        label: 'File Name',
                    read_length: -> { file_name_length }
          end
        end
      end
    end
  end
end
