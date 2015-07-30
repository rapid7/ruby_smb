module RubySMB
  module SMB1
    # This module holds the namespace for all SMB1 packets and related structures.
    module Packet
      autoload :SMBParameterBlock, 'ruby_smb/smb1/packet/smb_parameter_block'
      autoload :SMBHeader, 'ruby_smb/smb1/packet/smb_header'
      autoload :SMBDataBlock, 'ruby_smb/smb1/packet/smb_data_block'
      autoload :AndXBlock, 'ruby_smb/smb1/packet/andx_block'
    end
  end
end