module RubySMB
  module Fscc
    module FileInformation
      # The FileRenameInformation Class as defined in
      # [2.4.34.2 FileRenameInformation](https://msdn.microsoft.com/en-us/library/cc704597.aspx)
      class FileRenameInformation < BinData::Record
        # Null bytes because SMB1 Requests can't use this
        # Information Class.
        SMB1_FLAG = 0x0000
        # The value set in the InformationLevel field of an SMB2 request to indicate
        # the response should use this Information Class Structure.
        SMB2_FLAG = 0x0A

        endian :little
        
        uint8  :replace_if_exists,  label: 'Replace If Exists', initial_value: 1
        uint8  :reserved_0,         label: 'Reserved 0',        initial_value: 0
        uint16 :reserved_1,         label: 'Reserved 1',        initial_value: 0
        uint32 :reserved_2,         label: 'Reserved 2',        initial_value: 0
        uint64 :root_firectory,     label: 'Root Directory',    initial_value: 0
        uint32 :file_name_length,   label: 'File Name Length',  initial_value: 0
        string :file_name,          label: 'File Name',         initial_value: 1
        
      end
    end
  end
end
