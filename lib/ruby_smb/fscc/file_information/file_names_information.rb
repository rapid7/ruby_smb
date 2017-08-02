module RubySMB
  module Fscc
    module FileInformation
      # The FileNamesInformation Class as defined in
      # [2.4.26 FileNamesInformation](https://msdn.microsoft.com/en-us/library/cc232077.aspx)
      class FileNamesInformation < BinData::Record
        endian  :little

        uint32           :next_offset,      label: 'Next Entry Offset'
        uint32           :file_index,       label: 'File Index'
        uint32           :file_name_length, label: 'File Name Length',  initial_value: lambda { file_name.length }
        string16         :file_name,        label: 'File Name'


      end
    end
  end
end

