module RubySMB
  module Dcerpc
    module Gkdi

      # [2.2.2 FFC DH Parameters](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/e15ae269-ee21-446a-a480-de3ea243db5f)
      class GkdiFfcDhParameters < BinData::Record
        endian :little

        uint32      :parameters_length, initial_value: -> { (key_length * 2) + offset_of(generator) }
        uint8_array :magic, initial_length: 4, initial_value: [ 0x44, 0x48, 0x50, 0x4d ]
        uint32      :key_length
        uint8_array :field_order, initial_length: :key_length
        uint8_array :generator, initial_length: :key_length
      end
    end
  end
end
