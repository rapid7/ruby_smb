module RubySMB
  module Dcerpc
    class PSyntaxIdT < Ndr::NdrStruct
      default_parameter byte_align: 4
      endian :little

      uuid   :if_uuid,      initial_value: -> { uuid }
      ndr_uint16 :if_ver_major, initial_value: -> { ver_major }
      ndr_uint16 :if_ver_minor, initial_value: -> { ver_minor }
    end
  end
end
