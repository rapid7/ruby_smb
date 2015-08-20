module RubySMB
  module SMB1
    module Packet
      module NegotiateCommand
        # This class represents the Dialect for a NegotiateRequest.
        class Dialect < BinData::Record
          bit8    :buffer_format, :value => 0x2
          stringz :dialect_string, :assert => lambda { valid_dialect?(dialect_string)}

          def valid_dialect?(dialect)
            return [
              "NT LM 0.12",
              "SMB 2.002",
              "SMB 2.???"
            ].include?(dialect)
          end
        end
      end
    end
  end
end