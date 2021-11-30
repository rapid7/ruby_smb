module RubySMB
  module Fscc
    # Namespace and constant values for File Information Classes, as defined in
    # [2.4 File Information Classes](https://msdn.microsoft.com/en-us/library/cc232064.aspx)
    module FileInformation
      # Information class used in directory enumeration to return detailed
      # information about the contents of a directory.
      FILE_DIRECTORY_INFORMATION         = 0x01

      # Information class used in directory enumeration to return detailed
      # information (with extended attributes size) about the contents of a
      # directory.
      FILE_FULL_DIRECTORY_INFORMATION    = 0x02

      # Information class used in directory enumeration to return detailed
      # information (with extended attributes size and short names) about the
      # contents of a directory.
      FILE_BOTH_DIRECTORY_INFORMATION    = 0x03

      # Information class used to rename a file.
      FILE_RENAME_INFORMATION            = 0x0A

      # Information class used in directory enumeration to return detailed
      # information (with only filenames) about the contents of a directory.
      FILE_NAMES_INFORMATION             = 0x0C

      # Information class used to mark a file for deletion.
      FILE_DISPOSITION_INFORMATION       = 0x0D

      # This information class is used to query for information that is commonly
      # needed when a file is opened across a network.
      FILE_NETWORK_OPEN_INFORMATION      = 0x22

      # Information class used in directory enumeration to return detailed
      # information (with extended attributes size, short names and file ID)
      # about the contents of a directory.
      FILE_ID_BOTH_DIRECTORY_INFORMATION = 0x25

      # Information class used in directory enumeration to return detailed
      # information (with extended attributes size and file ID) about the
      # contents of a directory.
      FILE_ID_FULL_DIRECTORY_INFORMATION = 0x26


      # This information class is used to query the normalized name of a file. A
      # normalized name is an absolute pathname where each short name component
      # has been replaced with the corresponding long name component, and each
      # name component uses the exact letter casing stored on disk.
      FILE_NORMALIZED_NAME_INFORMATION = 0x30


      # These Information Classes can be used by SMB1 using the pass-through
      # Information Levels when available on the server (CAP_INFOLEVEL_PASSTHRU
      # capability flag in an SMB_COM_NEGOTIATE server response). The constant
      # SMB_INFO_PASSTHROUGH needs to be added to access these Information
      # Levels. This is documented in
      # [2.2.2.3.5 Pass-through Information Level Codes](https://msdn.microsoft.com/en-us/library/ff470158.aspx)
      SMB_INFO_PASSTHROUGH               = 0x03e8

      # The FILE_NAME_INFORMATION type as defined in
      # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/20406fb1-605f-4629-ba9a-c67ee25f23d2
      class FileNameInformation < BinData::Record
        endian :little
        uint32           :file_name_length, label: 'File Name Length',  initial_value: -> { file_name.do_num_bytes }
        string16         :file_name,        label: 'File Name',         read_length: -> { file_name_length }
      end

      require 'ruby_smb/fscc/file_information/file_directory_information'
      require 'ruby_smb/fscc/file_information/file_full_directory_information'
      require 'ruby_smb/fscc/file_information/file_disposition_information'
      require 'ruby_smb/fscc/file_information/file_id_full_directory_information'
      require 'ruby_smb/fscc/file_information/file_both_directory_information'
      require 'ruby_smb/fscc/file_information/file_id_both_directory_information'
      require 'ruby_smb/fscc/file_information/file_names_information'
      require 'ruby_smb/fscc/file_information/file_rename_information'
      require 'ruby_smb/fscc/file_information/file_network_open_information'
    end
  end
end
