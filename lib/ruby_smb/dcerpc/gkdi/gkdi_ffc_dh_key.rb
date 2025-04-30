module RubySMB
  module Dcerpc
    module Gkdi

      # [2.2.3.1 FFC DH Key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/f8770f01-036d-4bf6-a4cf-1bd0e3913404)
      class GkdiFfcDhKey < BinData::Record
        endian :little

        uint8_array :magic, initial_length: 4, initial_value: [ 0x44, 0x48, 0x50, 0x42 ]
        uint32      :key_length
        uint8_array :field_order, initial_length: :key_length
        uint8_array :generator, initial_length: :key_length
        uint8_array :public_key, initial_length: :key_length
      end
    end
  end
end
