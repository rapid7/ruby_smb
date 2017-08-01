module RubySMB
  # Contains the Constant values for File Information Classes, as defined in
  # [2.2.33 SMB2 QUERY_DIRECTORY Request](https://msdn.microsoft.com/en-us/library/cc246551.aspx)
  module FileInformation

    require 'ruby_smb/fscc/file_information/file_directory_information'

    # Basic information about a file or directory.
    # Basic information is defined as the file's name, time stamp, size and attributes.
    FILE_DIRECTORY_INFORMATION          = 0x01

    # Full information about a file or directory.
    # Full information is defined as all the basic information plus extended attribute size.
    FILE_FULL_DIRECTORY_INFORMATION     = 0x02

    # Full information plus volume file ID about a file or directory.
    # A volume file ID is defined as a number assigned by the underlying
    # object store that uniquely identifies a file within a volume.
    FILE_ID_FULL_DIRECTORY_INFORMATION  = 0x26

    # Basic information plus extended attribute size
    # and short name about a file or directory.
    FILE_BOTH_DIRECTORY_INFORMATION     = 0x03

    # FileBothDirectoryInformation plus volume file ID about a file or directory.
    FILE_ID_BOTH_DIRECTORY_INFORMATION  = 0x25

    # Detailed information on the names of files and directories in a directory.
    FILE_NAMES_INFORMATION              = 0x0C
  end
end