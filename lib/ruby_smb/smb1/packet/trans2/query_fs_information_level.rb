module RubySMB
  module SMB1
    module Packet
      module Trans2
        # SMB Query Information Levels as defined in
        # [2.2.8.2 QUERY_FS Information Levels](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/2c7707b4-afcd-4dbf-a0f3-35abebe68fac)
        # used in TRANS2_QUERY_FS_INFORMATION
        module QueryFsInformationLevel
          # Constants defined in
          # [2.2.2.3.2 QUERY_FS Information Level Codes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/55217a26-87ef-489f-a159-3ed6cc6412e9)
          # [dialect] description

          # [LANMAN2.0] Query file system allocation unit information.
          SMB_INFO_ALLOCATION               = 0x0001 # 1

          # [LANMAN2.0] Query volume name and serial number.
          SMB_INFO_VOLUME                   = 0x0002 # 2

          # [NT LANMAN] Query the creation timestamp, serial number, and Unicode-encoded volume label.
          SMB_QUERY_FS_VOLUME_INFO          = 0x0102 # 258

          # [NT LANMAN] Query 64-bit file system allocation unit information.
          SMB_QUERY_FS_SIZE_INFO            = 0x0103 # 259

          # [NT LANMAN] Query a file system's underlying device type and characteristics.
          SMB_QUERY_FS_DEVICE_INFO          = 0x0104 # 260

          # [NT LANMAN] Query file system attributes.
          SMB_QUERY_FS_ATTRIBUTE_INFO       = 0x0105 # 261

          def self.name(value)
            constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
          end

          require 'ruby_smb/smb1/packet/trans2/query_fs_information_level/query_fs_attribute_info'
        end
      end
    end
  end
end
