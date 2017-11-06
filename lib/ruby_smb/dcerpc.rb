module RubySMB
  # Namespace for structures and classes from File System
  # Control Codes as defined in
  # [[MS-FSCC]: File System Control Codes](https://msdn.microsoft.com/en-us/library/cc231987.aspx)
  module Dcerpc
    require 'ruby_smb/dcerpc/bind'
    require 'ruby_smb/dcerpc/request'
  end
end