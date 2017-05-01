module RubySMB
  module SMB1
    module Packet

      # Namespace for the Transaction2 sub-protocol documented in
      # [2.2.4.46 SMB_COM_TRANSACTION2 (0x32)](https://msdn.microsoft.com/en-us/library/ee441652.aspx)
      module Trans2
        require 'ruby_smb/smb1/packet/trans2/subcommands'
        require 'ruby_smb/smb1/packet/trans2/request'
        require 'ruby_smb/smb1/packet/trans2/open2_request'
      end
    end
  end
end