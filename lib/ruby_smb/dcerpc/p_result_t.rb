module RubySMB
  module Dcerpc
    class PResultT < Ndr::NdrStruct
      default_parameter byte_align: 4
      endian :little

      ndr_uint16        :result,          label: 'Presentation context negotiation results'
      ndr_uint16        :reason,          label: 'Rejection reason'
      p_syntax_id_t     :transfer_syntax, label: 'Presentation syntax ID',
        uuid:      -> { Ndr::UUID },
        ver_major: -> { Ndr::VER_MAJOR },
        ver_minor: -> { Ndr::VER_MINOR }
    end
  end
end