module RubySMB
  module Fscc
    module FileInformation
      # The FileBasicInformation Class as defined in
      # [2.4.7 FileBasicInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/16023025-8a78-492f-8b96-c873b042ac50)
      class FileBasicInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_BASIC_INFORMATION

        endian :little

        file_time       :create_time,     label: 'Create Time'
        file_time       :last_access,     label: 'Last Accessed Time'
        file_time       :last_write,      label: 'Last Write Time'
        file_time       :last_change,     label: 'Last Modified Time'
        file_attributes :file_attributes, label: 'File Attributes'
        string          :reserved,        label: 'Reserved', length: 4
      end
    end
  end
end
