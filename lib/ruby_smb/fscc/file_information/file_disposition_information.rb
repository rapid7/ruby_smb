module RubySMB
  module Fscc
    module FileInformation
      # The FileDispositionInformation Class as defined in
      # [2.4.11 FileDispositionInformation](https://msdn.microsoft.com/en-us/library/cc232098.aspx)
      class FileDispositionInformation < BinData::Record
        # Null bytes because SMB1 Requests can't use this
        # Information Class.
        SMB1_FLAG = 0x0000
        # The value set in the InformationLevel field of an SMB2 request to indicate
        # the response should use this Information Class Structure.
        SMB2_FLAG = 0x0D

        endian :little

        uint32 :buffer_length,      label: 'Buffer Length',   initial_value: 1
        uint16 :buffer_offset,      label: 'Buffer Offset',   initial_value: 96
        string :buffer,             label: 'Buffer',          initial_value: 1
      end
    end
  end
end
