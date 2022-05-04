module RubySMB
  module Fscc
    module FileInformation
      # The FileEaInformation Class as defined in
      # [2.4.12 FileEaInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/db6cf109-ead8-441a-b29e-cb2032778b0f)
      class FileEaInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_EA_INFORMATION

        endian :little

        uint32 :ea_size, label: 'Extended Attributes Size'
      end
    end
  end
end
