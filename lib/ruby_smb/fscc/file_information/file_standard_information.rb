module RubySMB
  module Fscc
    module FileInformation
      # The FileStandardInformation Class as defined in
      # [2.4.41 FileStandardInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5afa7f66-619c-48f3-955f-68c4ece704ae)
      class FileStandardInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_STANDARD_INFORMATION

        endian :little

        int64  :allocation_size, label: 'Allocation Size'
        int64  :end_of_file,     label: 'End of File'
        uint32 :number_of_links, label: 'Number of Links'
        int8   :delete_pending,  label: 'Delete Pending'
        int8   :directory,       label: 'Directory'
        string :reserved,        label: 'Reserved', length: 2
      end
    end
  end
end
