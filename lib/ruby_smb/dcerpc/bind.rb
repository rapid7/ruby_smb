module RubySMB
  module Dcerpc
    # The FileDirectoryInformation Class as defined in
    # http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm

    class PContElemT < BinData::Record
      endian :little

      uint16 :p_cont_id
      uint8 :n_transfer_syn, initial_value: 1
      uint8 :reserved
      choice :abstract_syntax, selection: -> {endpoint} do
        srv_svc_syntax Srvsvc
      end
      array :transfer_syntaxes, type: :ndr_syntax, initial_length: -> { n_transfer_syn }
    end

    class PContListT < BinData::Record
      endian :little

      uint8 :n_context_elem, initial_value: -> { 1 }
      uint8 :reserved
      uint16 :reserved2
      array :p_cont_elem, type: :p_cont_elem_t, initial_length: -> {n_context_elem}, endpoint: -> {endpoint}
    end

    class Bind < BinData::Record
      endian :little

      uint8 :rpc_vers, label: 'RPC version', initial_value: 5
      uint8 :rpc_vers_minor, label: 'minor version'
      uint8 :ptype, label: 'bind PDU', initial_value: 11
      uint8 :pfc_flags, label: 'flags', initial_value: 0x03

      uint32 :packed_drep, label: 'NDR data rep format label', initial_value: 16

      uint16 :frag_length, label: 'total length of fragment', initial_value: 72
      uint16 :auth_length, label: 'length of auth_value'
      uint32 :call_id, label: 'call identifier', initial_value: 1

      uint16 :max_xmit_frag, label: 'max transmit frag size', initial_value: 65535
      uint16 :max_recv_frag, label: 'max receive  frag size', initial_value: 65535
      uint32 :assoc_group_id, label: 'ncarnation of client-server assoc group'

      p_cont_list_t :p_context_elem, endpoint: -> { endpoint }
      string :auth_verifier_co_t
    end
  end
end
