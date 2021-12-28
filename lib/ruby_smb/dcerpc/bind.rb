module RubySMB
  module Dcerpc
    # The Bind PDU as defined in
    # [The bind PDU](http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_04_03)
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

    class Bind < BinData::Record
      PTYPE = PTypes::BIND

      endian :little

      # PDU Header
      pdu_header    :pdu_header, label: 'PDU header'
      ndr_uint16    :max_xmit_frag, label: 'max transmit frag size', initial_value: RubySMB::Dcerpc::MAX_XMIT_FRAG
      ndr_uint16    :max_recv_frag, label: 'max receive frag size', initial_value: RubySMB::Dcerpc::MAX_RECV_FRAG
      ndr_uint32    :assoc_group_id, label: 'incarnation of client-server assoc group'
      p_cont_list_t :p_context_list, label: 'Presentation context list', endpoint: -> { endpoint }

      # Auth Verifier
      sec_trailer   :sec_trailer, onlyif: -> { pdu_header.auth_length > 0 }
      string        :auth_value,
        onlyif: -> { pdu_header.auth_length > 0 },
        read_length: -> { pdu_header.auth_length }

      def initialize_instance
        super
        pdu_header.ptype = PTYPE
      end
    end
  end
end

