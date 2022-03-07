module RubySMB
  module SMB1
    module Packet
      module Trans2
        # Transaction2 subcommand constants as defined in
        # [2.2.6 Transaction2 Subcommands](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/1cc40e02-aaea-4f33-b7b7-3a6b63906516)
        module Subcommands
          OPEN2                    = 0x0000
          FIND_FIRST2              = 0x0001
          FIND_NEXT2               = 0x0002
          QUERY_FS_INFORMATION     = 0x0003
          SET_FS_INFORMATION       = 0x0004
          QUERY_PATH_INFORMATION   = 0x0005
          SET_PATH_INFORMATION     = 0x0006
          QUERY_FILE_INFORMATION   = 0x0007
          SET_FILE_INFORMATION     = 0x0008
          FSCTL                    = 0x0009
          IOCTL2                   = 0x000A
          FIND_NOTIFY_FIRST        = 0x000B
          FIND_NOTIFY_NEXT         = 0x000C
          CREATE_DIRECTORY         = 0x000D
          SESSION_SETUP            = 0x000E
          GET_DFS_REFERRAL         = 0x0010
          REPORT_DFS_INCONSISTENCY = 0x0011
        end
      end
    end
  end
end
