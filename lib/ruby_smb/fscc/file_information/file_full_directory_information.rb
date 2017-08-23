module RubySMB
  module Fscc
    module FileInformation
      # The FileFullDirectoryInformation Class as defined in
      # [2.4.14 FileFullDirectoryInformation](https://msdn.microsoft.com/en-us/library/cc232068.aspx)
      class FileFullDirectoryInformation < BinData::Record
        # The value set in the InformationLevel field of an SMB1 request to indicate
        # the response should use this Information Class Structure.
        SMB1_FLAG = 0x0102
        # The value set in the InformationLevel field of an SMB2 request to indicate
        # the response should use this Information Class Structure.
        SMB2_FLAG = 0x02

        endian  :little

        uint32           :next_offset,      label: 'Next Entry Offset'
        uint32           :file_index,       label: 'File Index'
        file_time        :create_time,      label: 'Create Time'
        file_time        :last_access,      label: 'Last Accessed Time'
        file_time        :last_write,       label: 'Last Write Time'
        file_time        :last_change,      label: 'Last Modified Time'
        uint64           :end_of_file,      label: 'End of File'
        uint64           :allocation_size,  label: 'Allocated Size'
        file_attributes  :file_attributes,  label: 'File Attributes'
        uint32           :file_name_length, label: 'File Name Length',          initial_value: lambda { file_name.do_num_bytes }
        uint32           :ea_size,          label: 'Extended Attributes Size'
        string16         :file_name,        label: 'File Name',                 read_length: lambda { file_name_length }


      end
    end
  end
end

