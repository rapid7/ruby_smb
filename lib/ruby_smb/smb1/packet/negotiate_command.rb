module RubySMB
  module SMB1
    module Packet

      # Namespace for all packets and structures related to the the SMB1
      # Negotiate command.
      module NegotiateCommand
        autoload :Request, 'ruby_smb/smb1/packet/negotiate_command/request'
        autoload :Response, 'ruby_smb/smb1/packet/negotiate_command/response'
        autoload :Dialect, 'ruby_smb/smb1/packet/negotiate_command/dialect'
        autoload :NTLMParameterBlock, 'ruby_smb/smb1/packet/negotiate_command/nt_lm_parameter_block'
      end
    end
  end
end