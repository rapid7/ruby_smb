module RubySMB
  module Fscc
    module FileInformation
      # The FileAlignmentInformation Class as defined in
      # [2.4.3 FileAlignmentInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/9b0b9971-85aa-4651-8438-f1c4298bcb0d)
      class FileAlignmentInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_ALIGNMENT_INFORMATION

        # If this value is specified, there are no alignment requirements for the device.
        FILE_BYTE_ALIGNMENT               = 0x00000000 # 0

        # If this value is specified, data MUST be aligned on a 2-byte boundary.
        FILE_WORD_ALIGNMENT               = 0x00000001 # 1

        # If this value is specified, data MUST be aligned on a 4-byte boundary.
        FILE_LONG_ALIGNMENT               = 0x00000003 # 3

        # If this value is specified, data MUST be aligned on an 8-byte boundary.
        FILE_QUAD_ALIGNMENT               = 0x00000007 # 7

        # If this value is specified, data MUST be aligned on a 16-byte boundary.
        FILE_OCTA_ALIGNMENT               = 0X0000000F # 15

        # If this value is specified, data MUST be aligned on a 32-byte boundary.
        FILE_32_BYTE_ALIGNMENT            = 0X0000001F # 31

        # If this value is specified, data MUST be aligned on a 64-byte boundary.
        FILE_64_BYTE_ALIGNMENT            = 0X0000003F # 63

        # If this value is specified, data MUST be aligned on a 128-byte boundary.
        FILE_128_BYTE_ALIGNMENT           = 0X0000007F # 127

        # If this value is specified, data MUST be aligned on a 256-byte boundary.
        FILE_256_BYTE_ALIGNMENT           = 0X000000FF # 255

        # If this value is specified, data MUST be aligned on a 512-byte boundary.
        FILE_512_BYTE_ALIGNMENT           = 0X000001FF # 511

        endian :little

        uint32  :alignment_requirement, label: 'Alignment Requirement', initial_value: FILE_BYTE_ALIGNMENT
      end
    end
  end
end
