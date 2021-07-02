module RubySMB
  module Dcerpc
    # The Bind ACK PDU as defined in
    # [The bind_ack PDU](http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_04_04)

    class PResultT < Ndr::NdrStruct
      default_parameter byte_align: 4
      endian :little

      ndr_uint16        :result,          label: 'Presentation context negotiation results'
      ndr_uint16        :reason,          label: 'Rejection reason'
      p_syntax_id_t :transfer_syntax, label: 'Presentation syntax ID',
        uuid: ->      { Ndr::UUID },
        ver_major: -> { Ndr::VER_MAJOR },
        ver_minor: -> { Ndr::VER_MINOR }
    end

    class PResultListT < Ndr::NdrStruct
      default_parameter byte_align: 4
      endian :little

      ndr_uint8  :n_results, label: 'Number of results'
      ndr_uint8  :reserved
      ndr_uint16 :reserved2
      array  :p_results, label: 'Results', type: :p_result_t, initial_length: -> { n_results }, byte_align: 4
    end

    class PortAnyT < Ndr::NdrStruct
      default_parameter byte_align: 2
      endian :little

      ndr_uint16  :str_length, label: 'Length', initial_value: -> { port_spec.to_binary_s.size }
      stringz :port_spec, label: 'Port string spec', byte_align: 2
    end

    class BindAck < BinData::Record
      # Presentation context negotiation results
      ACCEPTANCE         = 0
      USER_REJECTION     = 1
      PROVIDER_REJECTION = 2

      # Reasons for rejection of a context element
      REASON_NOT_SPECIFIED                     = 0
      ABSTRACT_SYNTAX_NOT_SUPPORTED            = 1
      PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED = 2
      LOCAL_LIMIT_EXCEEDED                     = 3

      endian :little

      pdu_header :pdu_header,         label: 'PDU header'

      ndr_uint16     :max_xmit_frag,      label: 'Max transmit frag size',  initial_value: RubySMB::Dcerpc::MAX_XMIT_FRAG
      ndr_uint16     :max_recv_frag,      label: 'Max receive frag size',   initial_value: RubySMB::Dcerpc::MAX_RECV_FRAG
      ndr_uint32     :assoc_group_id,     label: 'Association group ID'
      port_any_t :sec_addr,           label: 'Secondary address'

      p_result_list_t :p_result_list, label: 'Presentation context result list'
      string :auth_verifier, label: 'Authentication verifier',
        onlyif: -> { pdu_header.auth_length > 0 },
        read_length: -> { pdu_header.auth_length }

      def initialize_instance
        super
        pdu_header.ptype = RubySMB::Dcerpc::PTypes::BIND_ACK
      end
    end
  end
end

