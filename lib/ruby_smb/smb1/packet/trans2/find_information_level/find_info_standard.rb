module RubySMB
  module SMB1
    module Packet
      module Trans2
        module FindInformationLevel
          # SMB_INFO_STANDARD find result entry (LANMAN 2.0).
          # Used by TRANS2_FIND_FIRST2/FIND_NEXT2 on legacy servers
          # (e.g. Windows 95) that don't support NT LANMAN info levels.
          #
          # Unlike NT info levels, these entries have no next_offset field;
          # they are packed sequentially with a variable-length filename.
          class FindInfoStandard < BinData::Record
            CLASS_LEVEL = FindInformationLevel::SMB_INFO_STANDARD

            endian :little

            uint16  :creation_date,    label: 'Creation Date (SMB_DATE)'
            uint16  :creation_time,    label: 'Creation Time (SMB_TIME)'
            uint16  :last_access_date, label: 'Last Access Date'
            uint16  :last_access_time, label: 'Last Access Time'
            uint16  :last_write_date,  label: 'Last Write Date'
            uint16  :last_write_time,  label: 'Last Write Time'
            uint32  :data_size,        label: 'File Size'
            uint32  :allocation_size,  label: 'Allocation Size'
            uint16  :file_attributes,  label: 'File Attributes'
            uint8   :file_name_length, label: 'File Name Length'
            string  :file_name,        label: 'File Name',
                    read_length: -> { file_name_length }
          end
        end
      end
    end
  end
end
