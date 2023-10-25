module RubySMB
  module Dcerpc
    class PortAnyT < Ndr::NdrStruct
      default_parameter byte_align: 2
      endian :little

      ndr_uint16  :str_length, label: 'Length', initial_value: -> { port_spec.to_binary_s.size }
      stringz     :port_spec, label: 'Port string spec', byte_align: 2, onlyif: -> { str_length > 0 }
    end
  end
end