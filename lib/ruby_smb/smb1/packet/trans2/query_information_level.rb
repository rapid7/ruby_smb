module RubySMB
  module SMB1
    module Packet
      module Trans2
        # SMB Query Information Levels as defined in
        # [2.2.8.3 QUERY Information Levels](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/b9dcb99c-e810-4df8-ae29-cdf37e8c5a23)
        # used in TRANS2_QUERY_PATH_INFORMATION and TRANS2_QUERY_FILE_INFORMATION
        module QueryInformationLevel
          # Constants defined in
          # [2.2.2.3.3 QUERY Information Level Codes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/794afe2e-7c11-4a8c-b909-0a397966f6a9)
          # [dialect] description

          # [LANMAN2.0] Query creation, access, and last write timestamps, size and file attributes.
          SMB_INFO_STANDARD               = 0x0001 # 1

          # [LANMAN2.0] Query the SMB_INFO_STANDARD data along with the size of the file's extended attributes (EAs).
          SMB_INFO_QUERY_EA_SIZE          = 0x0002 # 2

          # [LANMAN2.0] Query a file's specific EAs by attribute name.
          SMB_INFO_QUERY_EAS_FROM_LIST    = 0x0003 # 3

          # [LANMAN2.0] Query all of a file's EAs.
          SMB_INFO_QUERY_ALL_EAS          = 0x0004 # 4

          # [LANMAN2.0] Validate the syntax of the path provided in the request. Not supported for TRANS2_QUERY_FILE_INFORMATION.
          SMB_INFO_IS_NAME_VALID          = 0x0006 # 6

          # [NT LANMAN] Query 64-bit create, access, write, and change timestamps along with extended file attributes.
          SMB_QUERY_FILE_BASIC_INFO       = 0x0101 # 257

          # [NT LANMAN] Query size, number of links, if a delete is pending, and if the path is a directory.
          SMB_QUERY_FILE_STANDARD_INFO    = 0x0102 # 258

          # [NT LANMAN] Query the size of the file's EAs.
          SMB_QUERY_FILE_EA_INFO          = 0x0103 # 259

          # [NT LANMAN] Query the long file name in Unicode format.
          SMB_QUERY_FILE_NAME_INFO        = 0x0104 # 260

          # [NT LANMAN] Query the SMB_QUERY_FILE_BASIC_INFO, SMB_QUERY_FILE_STANDARD_INFO, SMB_QUERY_FILE_EA_INFO, and SMB_QUERY_FILE_NAME_INFO data as well as access flags, access mode, and alignment information in a single request.
          SMB_QUERY_FILE_ALL_INFO         = 0x0107 # 263

          # [NT LANMAN] Query the 8.3 file name.<22>
          SMB_QUERY_FILE_ALT_NAME_INFO    = 0x0108 # 264

          # [NT LANMAN] Query file stream information.
          SMB_QUERY_FILE_STREAM_INFO      = 0x0109 # 265

          # [NT LANMAN] Query file compression information.
          SMB_QUERY_FILE_COMPRESSION_INFO = 0x010B # 267

          def self.name(value)
            constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
          end

          require 'ruby_smb/smb1/packet/trans2/query_information_level/query_file_basic_info'
          require 'ruby_smb/smb1/packet/trans2/query_information_level/query_file_standard_info'
        end
      end
    end
  end
end
