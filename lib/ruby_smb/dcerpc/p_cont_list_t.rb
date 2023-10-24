module RubySMB
  module Dcerpc
    # The presentation context list and its element as defined in
    # [Connection-oriented PDU Data Types - Declarations](https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03_01)
    class PContElemT < Ndr::NdrStruct
      default_parameter byte_align: 4
      endian :little

      ndr_uint16    :p_cont_id, label: 'Context ID'
      ndr_uint8     :n_transfer_syn, label: 'Number of transfer syntaxes', initial_value: 1
      ndr_uint8     :reserved
      p_syntax_id_t :abstract_syntax, label: 'Abstract syntax',
        uuid: ->      { endpoint::UUID },
        ver_major: -> { endpoint::VER_MAJOR },
        ver_minor: -> { endpoint::VER_MINOR }
      array         :transfer_syntaxes, label: 'Transfer syntax', type: :p_syntax_id_t,
        initial_length: -> { n_transfer_syn },
        uuid: ->      { Ndr::UUID },
        ver_major: -> { Ndr::VER_MAJOR },
        ver_minor: -> { Ndr::VER_MINOR },
        byte_align: 4
    end

    class PContListT < Ndr::NdrStruct
      default_parameter byte_align: 4
      endian :little

      ndr_uint8  :n_context_elem, label: 'Number of context elements', initial_value: -> { 1 }
      ndr_uint8  :reserved
      ndr_uint16 :reserved2
      array      :p_cont_elem, label: 'Presentation context elements', type: :p_cont_elem_t,
        initial_length: -> {n_context_elem},
        endpoint: -> {endpoint},
        byte_align: 4
    end
  end
end
