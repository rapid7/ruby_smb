module RubySMB
  module Nbss
    # The NM_FLAGS field of the NetBIOS Name Service header, as defined in
    # RFC 1002 section 4.2.1.1. The surrounding R/OPCODE and RCODE bits are
    # declared inline in the header records that embed this field
    # ({NodeStatusRequest} and {NodeStatusResponse}).
    class NameServiceHeaderFlags < BinData::Record
      endian :big

      bit1 :authoritative_answer, label: 'Authoritative Answer', initial_value: 0
      bit1 :truncated,            label: 'Truncated',            initial_value: 0
      bit1 :recursion_desired,    label: 'Recursion Desired',    initial_value: 0
      bit1 :recursion_available,  label: 'Recursion Available',  initial_value: 0
      bit2 :reserved,             label: 'Reserved',             initial_value: 0
      bit1 :broadcast,            label: 'Broadcast',            initial_value: 0
    end
  end
end
