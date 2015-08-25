module RubySMB
  module SMB1
    module Packet
      require "ruby_smb/smb1/packet/negotiate_command.rb"

      require 'ruby_smb/smb1/packet/smb_header'
      require 'ruby_smb/smb1/packet/parameter_block'
      require 'ruby_smb/smb1/packet/data_block'
      require 'ruby_smb/smb1/packet/negotiate_request'
    end
  end
end