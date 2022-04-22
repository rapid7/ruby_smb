module RubySMB
  module Fscc
    module FileInformation
      # The FileNameInformation Class as defined in
      # [2.4.27 FileNameInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/cb30e415-54c5-4483-a346-822ea90e1e89)
      class FileNameInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_NAME_INFORMATION

        endian :little

        uint32           :file_name_length, label: 'File Name Length',  initial_value: -> { file_name.do_num_bytes }
        string16         :file_name,        label: 'File Name',         read_length: -> { file_name_length }
      end
    end
  end
end
