module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_NEGOTIATE Request Packet as defined in
      # [2.2.4.52.1](https://msdn.microsoft.com/en-us/library/ee441572.aspx)
      class NegotiateRequest < BinData::Record

        # Represents the specific layout of the DataBlock for a NegotiateRequest Packet.
        class DataBlock < RubySMB::SMB1::Packet::DataBlock
          array :dialects, :label => 'Dialects', :type => :dialect,  :read_until => :eof
        end

        smb_header :header
        parameter_block :parameter_block
        data_block :data_block

        def initialize_instance
          super
          self.header.command = RubySMB::SMB1::COMMANDS[:SMB_COM_NEGOTIATE]
        end

        # Add an individual Dialect string to the list of
        # Dialects in the packet.
        #
        # @param dialect_string [String] The string representing the Dialect to be negotiated
        # @return [BinData::Array] A BinData array containing all the currently set dialects.
        def add_dialect(dialect_string)
          new_dialect = Dialect.new(dialect_string: dialect_string)
          data_block.dialects << new_dialect
        end

        # Sets the entire list of dialects for the Negotiate Request.
        #
        # @param dialect_array [Array<String>] An array of dialect strings to set on the packet
        # @return [BinData::Array] A BinData array containing all the currently set dialects.
        def set_dialects(dialect_array)
          data_block.dialects.clear
          dialect_array.each do |dialect_string|
            add_dialect(dialect_string)
          end
          data_block.dialects
        end

      end
    end
  end
end