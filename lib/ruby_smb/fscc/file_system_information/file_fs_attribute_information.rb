module RubySMB
  module Fscc
    module FileSystemInformation
      # The FileFsAttributeInformation
      # [2.5.1 FileFsAttributeInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ebc7e6e5-4650-4e54-b17c-cf60f6fbeeaa)
      class FileFsAttributeInformation < BinData::Record
        CLASS_LEVEL = FileSystemInformation::FILE_FS_ATTRIBUTE_INFORMATION

        endian :little
        struct   :file_system_attributes,            label: 'File System Attributes' do
          bit1   :file_supports_reparse_points,      label: 'FS Supports Reparse Points'
          bit1   :file_supports_sparse_files,        label: 'FS Supports Sparse Files'
          bit1   :file_volume_quotas,                label: 'FS Supports Quotas'
          bit1   :file_file_compression,             label: 'FS Supports File Compression'
          bit1   :file_persistent_acls,              label: 'FS Supports Persistent ACLs'
          bit1   :file_unicode_on_disk,              label: 'FS Supports Unicode Names'
          bit1   :file_case_preserved_names,         label: 'FS Preserves Name Casing'
          bit1   :file_case_sensitive_search,        label: 'FS Supports Case-Sensitive Searching'
          # byte boundary
          bit1   :file_volume_is_compressed,         label: 'FS Is Compressed'
          bit6   :reserved0
          bit1   :file_supports_remote_storage,      label: 'FS Supports Remote Storage'
          # byte boundary
          bit1   :file_supports_extended_attributes, label: 'FS Supports Persistent Extended Attributes'
          bit1   :file_supports_hard_links,          label: 'FS Supports Hard Links'
          bit1   :file_supports_transactions,        label: 'FS Supports Transactions'
          bit1   :file_sequential_write_once,        label: 'FS Is Write Once'
          bit1   :file_read_only_volume,             label: 'FS Is Read-Only'
          bit1   :file_named_streams,                label: 'FS Supports Named Streams'
          bit1   :file_supports_encryption,          label: 'FS Supports Encryption'
          bit1   :file_supports_object_ids,          label: 'FS Supports Object IDs'
          # byte boundary
          bit3   :reserved1
          bit1   :file_supports_sparse_vdl,          label: 'FS Supports Sparse VDL'
          bit1   :file_supports_block_refcounting,   label: 'FS Supports Block Reference Counting'
          bit1   :file_supports_integrity_streams,   label: 'FS Supports Integrity Streams'
          bit1   :file_supports_usn_journal,         label: 'FS Supports USN Change Journal'
          bit1   :file_supports_open_by_file_id,     label: 'FS Supports Open By File ID'
        end
        int32    :maximum_component_name_length,     label: 'Maximum Component Name Length'
        uint32   :file_system_name_length,           label: 'File System Name Length', initial_value: -> { file_system_name.do_num_bytes }
        string16 :file_system_name,                  label: 'File System Name', read_length: -> { file_system_name_length }
      end
    end
  end
end
