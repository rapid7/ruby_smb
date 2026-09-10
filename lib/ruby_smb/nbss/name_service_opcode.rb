module RubySMB
  module Nbss
    # The R (response) bit and 4-bit OPCODE that open the second word of the
    # NetBIOS Name Service header, as defined in RFC 1002 section 4.2.1.1.
    class NameServiceOpcode < BinData::Record
      endian :big

      bit1 :response, label: 'Response', initial_value: 0
      bit4 :opcode,   label: 'Opcode',   initial_value: 0
    end
  end
end
