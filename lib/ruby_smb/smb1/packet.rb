module RubySMB
  module Smb1
    # This module holds the namespace for all SMB1 packets and related structures.
    module Packet
      autoload :SmbParameterBlock, 'ruby_smb/smb1/packet/smb_parameter_block'
    end
  end
end