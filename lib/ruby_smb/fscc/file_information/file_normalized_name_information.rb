module RubySMB
  module Fscc
    module FileInformation
      # The FileNormalizedNameInformation Class as defined in
      # [2.4.30 FileNormalizedNameInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/20bcadba-808c-4880-b757-4af93e41edf6)
      class FileNormalizedNameInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_NORMALIZED_NAME_INFORMATION

        endian :little

        uint32           :file_name_length, label: 'File Name Length',  initial_value: -> { file_name.do_num_bytes }
        string16         :file_name,        label: 'File Name',         read_length: -> { file_name_length }
      end
    end
  end
end
