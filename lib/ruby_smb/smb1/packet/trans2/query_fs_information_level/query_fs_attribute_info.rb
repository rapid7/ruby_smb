module RubySMB
  module SMB1
    module Packet
      module Trans2
        # SMB_QUERY_FS_ATTRIBUTE_INFO Class as defined in
        # [2.2.8.2.6 SMB_QUERY_FS_ATTRIBUTE_INFO](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/1011206a-55c5-4dbf-aff0-119514136940)
        module QueryFsInformationLevel
          class QueryFsAttributeInfo < BinData::Record
            CLASS_LEVEL = SMB_QUERY_FS_ATTRIBUTE_INFO
            endian :little

            struct :flags, label: 'Flags' do
              bit3   :reserved1
              bit1   :file_file_compression,      label: 'File Compression'
              bit1   :file_persistent_acls,       label: 'Persistent ACLs'
              bit1   :file_unicode_on_disk,       label: 'Unicode on Disk'
              bit1   :file_case_preserved_names,  label: 'Case Preserved Names'
              bit1   :file_case_sensitive_search, label: 'Case Sensitive Search'
              # byte boundary
              bit1   :file_volume_is_compressed,  label: 'Volume is Compressed'
              bit23  :reserved2
            end
          end
        end
      end
    end
  end
end
