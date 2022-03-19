module RubySMB
  module Fscc
    module FileInformation
      # The FileAlignmentInformation Class as defined in
      # [2.4.3 FileAlignmentInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/9b0b9971-85aa-4651-8438-f1c4298bcb0d)
      class FileAlignmentInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_ALIGNMENT_INFORMATION

        endian :little

        uint32  :alignment_requirement, label: 'Alignment Requirement'
      end
    end
  end
end
