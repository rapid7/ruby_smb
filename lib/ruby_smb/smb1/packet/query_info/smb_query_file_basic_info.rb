module RubySMB
  module SMB1
    module Packet
      # SMB_QUERY_FILE_BASIC_INFO Class as defined in
      # [2.2.8.3.6 SMB_QUERY_FILE_BASIC_INFO](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/3da7df75-43ba-4498-a6b3-a68ba57ec922)
      module QueryInfo
        class SmbQueryFileBasicInfo < BinData::Record
          INFORMATION_LEVEL = SMB_QUERY_FILE_BASIC_INFO
          endian :little

          file_time                :create_time,         label: 'Create Time'
          file_time                :last_access,         label: 'Last Accessed Time'
          file_time                :last_write,          label: 'Last Write Time'
          file_time                :last_change,         label: 'Last Modified Time'
          smb_ext_file_attributes  :ext_file_attributes, label: 'Extended File Attributes'
          uint32                   :reserved,            label: 'Reserved'
        end
      end
    end
  end
end
