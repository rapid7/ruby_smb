module RubySMB
  module SMB1
    module Packet
      module NegotiateCommand

        # Represents a SMB1 Negotiate request packet.
        # [2.2.4.52.1 Request](https://msdn.microsoft.com/en-us/library/ee441572.aspx)
        class Request < BinData::Record
          smb_header            :smb_header
          smb_parameter_block   :smb_parameter_block
          smb_data_block        :smb_data_block

          def initialize_command
            smb_header.command = RubySMB::SMB1::COMMANDS[:SMB_COM_NEGOTIATE]
            self
          end

          def set_dialects(dialects=[])
            raise ArgumentError, 'Must be an Array of Dialects' unless dialects.kind_of? Enumerable

            dialects_block = BinData::Array.new(:type => :dialect)
            dialects_block.assign(dialects)
            smb_data_block.bytes = dialects_block.to_binary_s
            self
          end
        end
      end
    end
  end
end