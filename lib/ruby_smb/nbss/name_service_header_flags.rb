module RubySMB
  module Nbss
    # NetBIOS Name Service header flags, as defined in RFC 1002 section 4.2.1.1.
    class NameServiceHeaderFlags < BinData::Record
      endian :big

      bit1 :response,             label: 'Response',             initial_value: 0
      bit4 :opcode,               label: 'Opcode',               initial_value: 0
      bit1 :authoritative_answer, label: 'Authoritative Answer', initial_value: 0
      bit1 :truncated,            label: 'Truncated',            initial_value: 0
      bit1 :recursion_desired,    label: 'Recursion Desired',    initial_value: 0
      bit1 :recursion_available,  label: 'Recursion Available',  initial_value: 0
      bit2 :reserved,             label: 'Reserved',             initial_value: 0
      bit1 :broadcast,            label: 'Broadcast',            initial_value: 0
      bit4 :rcode,                label: 'Result Code',          initial_value: 0
    end
  end
end
