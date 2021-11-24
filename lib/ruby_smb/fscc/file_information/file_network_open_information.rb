module RubySMB
  module Fscc
    module FileInformation
      # The FileNetworkOpenInformation Class as defined in
      # [2.4.29 FileNetworkOpenInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/26d261db-58d1-4513-a548-074448cbb146)
      class FileNetworkOpenInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_NETWORK_OPEN_INFORMATION

        endian :little

        file_time        :create_time,        label: 'Create Time'
        file_time        :last_access,        label: 'Last Accessed Time'
        file_time        :last_write,         label: 'Last Write Time'
        file_time        :last_change,        label: 'Last Modified Time'
        uint64           :allocation_size,    label: 'Allocated Size'
        uint64           :end_of_file,        label: 'End of File'
        file_attributes  :file_attributes,    label: 'File Attributes'
        uint32           :reserved,           label: 'Reserved Space'
      end
    end
  end
end
