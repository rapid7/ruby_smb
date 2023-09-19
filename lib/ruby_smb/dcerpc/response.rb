module RubySMB
  module Dcerpc
    # The Response PDU as defined in
    # [The response PDU](http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_04_10)
    class Response < BinData::Record
      PTYPE = PTypes::RESPONSE

      endian :little

      # PDU Header
      pdu_header  :pdu_header, label: 'PDU header common fields'
      uint32      :alloc_hint, label: 'Allocation hint',  initial_value: -> { stub.do_num_bytes }
      uint16      :p_cont_id, label: 'Presentation context identification'
      uint8       :cancel_count, label: 'Cancel count'
      uint8       :reserved

      # PDU Body
      string      :stub, label: 'Stub', read_length: -> { stub_length }

      # Auth Verifier
      sec_trailer :sec_trailer, onlyif: -> { has_auth_verifier? }
      string      :auth_value, label: 'Authentication verifier',
        onlyif: -> { has_auth_verifier? },
        read_length: -> { pdu_header.auth_length }

      def initialize_instance
        super
        pdu_header.ptype = PTYPE
      end

      def has_auth_verifier?
        self.pdu_header.auth_length > 0
      end

      def stub_length
        stub_length = pdu_header.frag_length - stub.rel_offset
        if has_auth_verifier?
          # Note that the resulting stub length includes auth_pad. We will be
          # able to separate the auth_pad from the stub once the sec_trailer
          # structure is read.
          stub_length -= (sec_trailer.num_bytes + pdu_header.auth_length)
        end
        stub_length
      end
    end
  end
end
