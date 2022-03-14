module RubySMB
  module Fscc
    module FileInformation
      # The FilePositionInformation Class as defined in
      # [2.4.35 FilePositionInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e3ce4a39-327e-495c-99b6-6b61606b6f16)
      class FilePositionInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_POSITION_INFORMATION

        endian :little

        int64  :current_byte_offset, label: 'Current Byte Offset'
      end
    end
  end
end
