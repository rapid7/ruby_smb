module RubySMB
  module Dcerpc
    # The Alter context PDU as defined in
    # [The alter_context PDU](https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_04_01)
    class AlterContext < BinData::Record
      PTYPE = PTypes::ALTER_CONTEXT

      endian :little

      # PDU Header
      pdu_header    :pdu_header, label: 'PDU header'
      ndr_uint16    :max_xmit_frag, label: 'Max transmit frag size', initial_value: RubySMB::Dcerpc::MAX_XMIT_FRAG
      ndr_uint16    :max_recv_frag, label: 'Max receive frag size', initial_value: RubySMB::Dcerpc::MAX_RECV_FRAG
      ndr_uint32    :assoc_group_id, label: 'Incarnation of client-server assoc group'
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

