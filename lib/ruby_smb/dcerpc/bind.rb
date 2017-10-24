module RubySMB
  module Dcerpc
    # The FileDirectoryInformation Class as defined in
    # [2.4.18 FileIdFullDirectoryInformation](https://msdn.microsoft.com/en-us/library/cc232071.aspx)

    class PSyntaxIdT < BinData::Record
      endian  :little

      # string :if_uuid, initial_value: '4b324fc8-1670-01d3-1278-5a47bf6ee188'
      # uint32  :if_version, initial_value: 3

      #uint128be :to_uuid, initial_value: '4b324fc8-1670-01d3-1278-5a47bf6ee188'.gsub(/-/, '').to_i(16)
      string :to_uuid, initial_value: -> {
        parts = '4b324fc8-1670-01d3-1278-5a47bf6ee188'.split('-')
        return [ parts[0].hex, parts[1].hex, parts[2].hex, parts[3].hex ].pack('Vvvn') + [ parts[4] ].pack('H*')
      }
      uint16  :if_ver, initial_value: 3
      uint16  :if_ver_minor, initial_value: 0

    end

    class PContElemT < BinData::Record
      endian :little

      uint16           :p_cont_id
      uint8            :n_transfer_syn, initial_value: 1
      uint8            :reserved
      p_syntax_id_t    :abstract_syntax
      array            :transfer_syntaxes, :type => :p_syntax_id_t
    end

    class PContListT < BinData::Record
      endian :little

      uint8  :n_context_elem, initial_value: 2
      uint8  :reserved
      uint16 :reserved2
      array  :p_cont_elem, :type => :p_cont_elem_t
    end

    class Bind < BinData::Record
      endian :little

      uint8           :rpc_vers,       label: 'RPC version', initial_value: 5
      uint8           :rpc_vers_minor, label: 'minor version', initial_value: 0
      uint8           :ptype,          label: 'bind PDU', initial_value: 11
      uint8           :pfc_flags,      label: 'flags', initial_value: 0x03

      uint32          :packed_drep,    label: 'NDR data rep format label', initial_value: 16

      uint16          :frag_length,    label: 'total length of fragment', initial_value: 116
      uint16          :auth_length,    label: 'length of auth_value', initial_value: 0
      uint32          :call_id,        label: 'call identifier', initial_value: 2

      uint16          :max_xmit_frag,  label: 'max transmit frag size', initial_value: 4280
      uint16          :max_recv_frag,  label: 'max receive  frag size', initial_value: 4280
      uint32          :assoc_group_id, label: 'ncarnation of client-server assoc group', initial_value: 0x00000000

      p_cont_list_t   :p_context_elem

    end
  end
end
