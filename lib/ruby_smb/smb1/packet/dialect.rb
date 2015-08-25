module RubySMB
  module SMB1
    module Packet
      # This class represents the Dialect for a NegotiateRequest.
      class Dialect < BinData::Record
        bit8 :buffer_format, :value => 0x2
        stringz :dialect_string
      end
    end
  end
end