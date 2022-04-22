module RubySMB
  module Fscc
    # Namespace and constant values for File System Information Classes, as defined in
    # [2.5 File System Information Classes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ee12042a-9352-46e3-9f67-c094b75fe6c3)
    module FileSystemInformation
      FILE_FS_VOLUME_INFORMATION       = 1
      FILE_FS_LABEL_INFORMATION        = 2
      FILE_FS_SIZE_INFORMATION         = 3
      FILE_FS_DEVICE_INFORMATION       = 4
      FILE_FS_ATTRIBUTE_INFORMATION    = 5
      FILE_FS_CONTROL_INFORMATION      = 6
      FILE_FS_FULL_SIZE_INFORMATION    = 7
      FILE_FS_OBJECT_ID_INFORMATION    = 8
      FILE_FS_DRIVER_PATH_INFORMATION  = 9
      FILE_FS_VOLUME_FLAGS_INFORMATION = 10
      FILE_FS_SECTOR_SIZE_INFORMATION  = 11

      def self.name(value)
        constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
      end

      require 'ruby_smb/fscc/file_system_information/file_fs_attribute_information'
      require 'ruby_smb/fscc/file_system_information/file_fs_volume_information'
    end
  end
end
