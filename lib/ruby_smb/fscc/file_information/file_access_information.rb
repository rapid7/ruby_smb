module RubySMB
  module Fscc
    module FileInformation
      # The FileAccessInformation Class as defined in
      # [2.4.1 FileAccessInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/01cf43d2-deb3-40d3-a39b-9e68693d7c90)
      class FileAccessInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_ACCESS_INFORMATION

        endian :little

        uint32  :access_flags, label: 'Access Flags'
      end
    end
  end
end
