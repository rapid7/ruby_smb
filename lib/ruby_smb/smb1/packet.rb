module RubySMB
  module SMB1
    # This module holds the namespace for all SMB1 packets and related structures.
    module Packet
      require 'ruby_smb/smb1/packet/smb_parameter_block.rb'
      require 'ruby_smb/smb1/packet/smb_header.rb'
      require 'ruby_smb/smb1/packet/smb_data_block.rb'
      require 'ruby_smb/smb1/packet/andx_block.rb'

      autoload :NegotiateCommand, 'ruby_smb/smb1/packet/negotiate_command'
      autoload :ResponseHelper, 'ruby_smb/smb1/packet/response_helper'
    end
  end
end