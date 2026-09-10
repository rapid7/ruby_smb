module RubySMB
  module Nbss
    # The 4-bit RCODE that closes the second word of the NetBIOS Name Service
    # header, as defined in RFC 1002 section 4.2.1.1.
    class NameServiceResultCode < BinData::Record
      endian :big

      bit4 :rcode, label: 'Result Code', initial_value: 0
    end
  end
end
