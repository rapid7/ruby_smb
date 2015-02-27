# A packet parsing and manipulation library for the SMB2 protocol
# [[MS-SMB2] Server Message Block (SMB) Protocol Versions 2 and 3](https://msdn.microsoft.com/en-us/library/cc246482.aspx)

module Smb2
  autoload :Version, 'smb2/version'
  autoload :Packet, 'smb2/packet'
  autoload :Dispatcher, 'smb2/dispatcher'
  autoload :Client, 'smb2/client'

  # [[MS-SMB2] 2.2 Message Syntax](https://msdn.microsoft.com/en-us/library/cc246497.aspx)
  COMMANDS = {
    NEGOTIATE:        0x00,
    SESSION_SETUP:    0x01,
    LOGOFF:           0x02,
    TREE_CONNECT:     0x03,
    TREE_DISCONNECT:  0x04,
    CREATE:           0x05,
    CLOSE:            0x06,
    FLUSH:            0x07,
    READ:             0x08,
    WRITE:            0x09,
    LOCK:             0x0a,
    IOCTL:            0x0b,
    CANCEL:           0x0c,
    QUERY_DIRECTORY:  0x0e,
    ECHO:             0x0d,
    CHANGE_NOTIFY:    0x0f,
    QUERY_INFO:       0x10,
    SET_INFO:         0x11,
  }.freeze
end

