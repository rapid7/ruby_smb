module RubySMB
  module Dcerpc
    # The FileDirectoryInformation Class as defined in
    # http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm

    class PSyntaxIdT < BinData::Record
      endian :little
      uuid :if_uuid
      uint16 :if_ver
      uint16 :if_ver_minor
    end

    class PSyntaxIdT1 < BinData::Record
      endian :little
      uuid :if_uuid
      uint16 :if_ver
      uint16 :if_ver_minor
    end

    class PContElemT < BinData::Record
      endian :little

      uint16 :p_cont_id, initial_value: 0
      uint8 :n_transfer_syn, value: -> { transfer_syntaxes.length }
      uint8 :reserved
      p_syntax_id_t :abstract_syntax
      array :transfer_syntaxes, type: :p_syntax_id_t1, initial_length: 1
    end

    class PContListT < BinData::Record
      endian :little

      uint8 :n_context_elem, value: -> { p_cont_elem.length }
      uint8 :reserved
      uint16 :reserved2
      array :p_cont_elem, type: :p_cont_elem_t, initial_length: 1
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

      #p_cont_list_t :p_context_elem
    end
  end
end
