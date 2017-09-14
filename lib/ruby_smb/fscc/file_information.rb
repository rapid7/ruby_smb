module RubySMB
  module Fscc
    # Contains the Constant values for File Information Classes, as defined in
    # [2.2.33 SMB2 QUERY_DIRECTORY Request](https://msdn.microsoft.com/en-us/library/cc246551.aspx)
    module FileInformation
      require 'ruby_smb/fscc/file_information/file_directory_information'
      require 'ruby_smb/fscc/file_information/file_full_directory_information'
      require 'ruby_smb/fscc/file_information/file_disposition_information'
      require 'ruby_smb/fscc/file_information/file_id_full_directory_information'
      require 'ruby_smb/fscc/file_information/file_both_directory_information'
      require 'ruby_smb/fscc/file_information/file_id_both_directory_information'
      require 'ruby_smb/fscc/file_information/file_names_information'
    end
  end
end
