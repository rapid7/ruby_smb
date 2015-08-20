# This module adds the namespace for version 1 of the SMB Protocol
# as defined in [MS-SMB](https://msdn.microsoft.com/en-us/library/cc246231.aspx)
module RubySMB::SMB1
  autoload :Packet, 'ruby_smb/smb1/packet'


  COMMANDS = {
    SMB_COM_NEGOTIATE: 0x72,
    SMB_COM_NO_ANDX_COMMAND: 0xFF
  }
  # Protocol ID value. Translates to \xFFSMB
  SMB_PROTOCOL_ID = 0xFF534D42


  # null terminator string value.
  NULL_TERMINATOR = "\x00"
end