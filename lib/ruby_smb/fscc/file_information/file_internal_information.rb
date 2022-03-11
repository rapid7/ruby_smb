module RubySMB
  module Fscc
    module FileInformation
      # The FileInternalInformation Class as defined in
      # [2.4.22 FileInternalInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/7d796611-2fa5-41ac-8178-b6fea3a017b3)
      class FileInternalInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_ID_FULL_DIRECTORY_INFORMATION

        endian :little

        uint64 :file_id, label: 'File ID'
      end
    end
  end
end
