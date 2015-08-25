module RubySMB
  module SMB1
    module Packet
      class NegotiateRequest < BinData::Record

        # Represents the specific layout of the DataBlock for a NegotiateRequest Packet.
        class DataBlock < RubySMB::SMB1::Packet::DataBlock
          array :dialects, :type => :dialect,  :read_until => :eof
        end

        smb_header :header
        parameter_block :parameter_block
        data_block :data_block

        def initialize_instance
          super
          self.header.command = RubySMB::SMB1::COMMANDS[:SMB_COM_NEGOTIATE]
        end

        def add_dialect(dialect_string)
          new_dialect = Dialect.new(dialect_string: dialect_string)
          data_block.dialects << new_dialect
        end

        def set_dialects(dialect_array)
          dialect_array.each do |dialect_string|
            add_dialect(dialect_string)
          end
        end

      end
    end
  end
end