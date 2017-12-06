module RubySMB
  module Dcerpc
    # The FileDirectoryInformation Class as defined in
    # http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm

    class SrvsvcSyntax < BinData::Record
      endian :little
      uuid   :if_uuid, value: '4b324fc8-1670-01d3-1278-5a47bf6ee188'
      uint16 :if_ver, initial_value: 3
      uint16 :if_ver_minor, initial_value: 0
    end

    class NdrSyntax < BinData::Record
      endian :little
      uuid   :if_uuid, value: '8a885d04-1ceb-11c9-9fe8-08002b104860'
      uint16 :if_ver, initial_value: 2
      uint16 :if_ver_minor, initial_value: 0
    end

    class PContElemT < BinData::Record
      endian :little

      uint16 :p_cont_id
      uint8 :n_transfer_syn, value: -> { transfer_syntaxes.length }
      uint8 :reserved
      choice :abstract_syntax, selection: -> {endpoint} do
        srvsvc_syntax Srvsvc
      end
      array :transfer_syntaxes, type: :ndr_syntax, initial_length: 1
    end

    class PContListT < BinData::Record
      endian :little

      uint8 :n_context_elem, value: -> { p_cont_elem.length }
      uint8 :reserved
      uint16 :reserved2
      array :p_cont_elem, type: :p_cont_elem_t, initial_length: 1, endpoint: -> {endpoint}
    end

    class Bind < BinData::Record
      endian :little

      uint8 :rpc_vers, label: 'RPC version', initial_value: 5
      uint8 :rpc_vers_minor, label: 'minor version', initial_value: 0
      uint8 :ptype, label: 'bind PDU', initial_value: 11
      uint8 :pfc_flags, label: 'flags', initial_value: 0x03

      uint32 :packed_drep, label: 'NDR data rep format label', initial_value: 16

      uint16 :frag_length, label: 'total length of fragment', initial_value: 72
      uint16 :auth_length, label: 'length of auth_value', initial_value: 0
      uint32 :call_id, label: 'call identifier', initial_value: 1

      uint16 :max_xmit_frag, label: 'max transmit frag size', initial_value: 65535
      uint16 :max_recv_frag, label: 'max receive  frag size', initial_value: 65535
      uint32 :assoc_group_id, label: 'ncarnation of client-server assoc group', initial_value: 0x00000000

      p_cont_list_t :p_context_elem, endpoint: -> {endpoint}
    end
  end
end
