# A packet parsing and manipulation library for the SMB1 and SMB2 protocols
#
# [[MS-SMB] Server Mesage Block (SMB) Protocol Version 1](https://msdn.microsoft.com/en-us/library/cc246482.aspx)
# [[MS-SMB2] Server Mesage Block (SMB) Protocol Versions 2 and 3](https://msdn.microsoft.com/en-us/library/cc246482.aspx)
module RubySMB
  autoload :Dispatcher, 'ruby_smb/dispatcher'
  autoload :VERSION, 'ruby_smb/version'
  autoload :Version, 'ruby_smb/version'
  autoload :Smb2, 'ruby_smb/smb2'
end