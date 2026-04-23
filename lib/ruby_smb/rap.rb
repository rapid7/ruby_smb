module RubySMB
  # Remote Administration Protocol (RAP), as defined in [MS-RAP]
  # (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rap/).
  # RAP is the LAN Manager remote-administration API, carried over the
  # `\PIPE\LANMAN` named pipe using SMB1 SMB_COM_TRANSACTION. It is the only
  # share-enumeration path supported by pre-NT servers (e.g. Windows 95/98/ME).
  module Rap
    require 'ruby_smb/rap/net_share_enum'
  end
end
