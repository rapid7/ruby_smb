module RubySMB
  module SMB1
    module Packet
      module Trans2
        # SMB_QUERY_FILE_STANDARD_INFO Class as defined in
        # [2.2.8.3.7 SMB_QUERY_FILE_STANDARD_INFO](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/3bdd080c-f8a4-4a09-acf1-0f8bd00152e4)
        module QueryInformationLevel
          class QueryFileStandardInfo < BinData::Record
            CLASS_LEVEL = SMB_QUERY_FILE_STANDARD_INFO
            endian :little

            uint64  :allocation_size, label: 'Allocated Size'
            uint64  :end_of_file,     label: 'End of File'
            uint32  :number_of_links, label: 'Number of Hard Links'
            uint8   :delete_pending,  label: 'Delete Pending?'
            uint8   :directory,       label: 'Directory?'
          end
        end
      end
    end
  end
end
