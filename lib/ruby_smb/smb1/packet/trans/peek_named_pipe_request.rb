module RubySMB
  module SMB1
    module Packet
      module Trans
        # This class represents an SMB1 Trans PeekNamedPipe Request Packet as defined in
        # [2.2.5.5.1 Request](https://msdn.microsoft.com/en-us/library/ee442106.aspx)
        class PeekNamedPipeRequest < RubySMB::SMB1::Packet::Trans::Request

          def fid=(file_id)
            parameter_block.setup = [RubySMB::SMB1::Packet::Trans::Subcommands::PEEK_NAMED_PIPE, file_id]
          end

          def initialize_instance
            super
            smb_header.command = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION
            data_block.name = "\\PIPE\\"
            parameter_block.setup << RubySMB::SMB1::Packet::Trans::Subcommands::PEEK_NAMED_PIPE
            parameter_block.setup_count = 2
          end
        end
      end
    end
  end
end
