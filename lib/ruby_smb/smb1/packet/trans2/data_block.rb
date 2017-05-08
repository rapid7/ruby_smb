module RubySMB
  module SMB1
    module Packet
      module Trans2

        # Extends the {RubySMB::SMB1::DataBlock} to include padding methods
        # that all Trans2 DataBlocks will need to handle proper byte alignment.
        class DataBlock < RubySMB::SMB1::DataBlock
          private

          # Determines the correct length for the padding in front of
          # #trans2_parameters. It should always force a 4-byte alignment.
          def pad1_length
            offset = (name.abs_offset + 1) % 4
            (4 - offset) % 4
          end

          # Determines the correct length for the padding in front of
          # #trans2_data. It should always force a 4-byte alignment.
          def pad2_length
            offset = (trans2_parameters.abs_offset + trans2_parameters.length) % 4
            (4 - offset) % 4
          end
        end
      end
    end
  end
end