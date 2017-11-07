module RubySMB
  module Fscc
    module FileInformation
      # The FileRenameInformation Class as defined in
      # [2.4.34.2 FileRenameInformation](https://msdn.microsoft.com/en-us/library/cc704597.aspx)
      class FileRenameInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_ID_FULL_DIRECTORY_INFORMATION

        endian :little

        uint8  :replace_if_exists,  label: 'Replace If Exists'
        uint8  :reserved_0,         label: 'Reserved 0',        initial_value: 0
        uint16 :reserved_1,         label: 'Reserved 1',        initial_value: 0
        uint32 :reserved_2,         label: 'Reserved 2',        initial_value: 0
        uint64 :root_firectory,     label: 'Root Directory',    initial_value: 0
        uint32 :file_name_length,   label: 'File Name Length',  initial_value: -> { file_name.do_num_bytes }
        string :file_name,          label: 'File Name',           read_length: -> { file_name_length }

      end
    end
  end
end
