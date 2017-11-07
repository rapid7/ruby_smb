module RubySMB
  module Dcerpc

    class Request < BinData::Record
      endian :big

      #common fields
      uint8 :rpc_vers, initial_value: 5 # 00:01 RPC version
      uint8 :rpc_vers_minor, initial_value: 0 # 01:01 minor version
      uint8 :ptype, initial_value: 0 # 02:01 request PDU
      uint8 :pfc_flags, initial_value: 0x00000003 # 03:01 flags

      uint32 :packed_drep, initial_value: 10000000 # 04:04 NDR data rep format label

      uint16 :frag_length, initial_value: -> { self.do_num_bytes } # 08:02 total length of fragment
      uint16 :auth_length, initial_value: 0 # 10:02 length of auth_value
      uint32 :call_id, initial_value: 0 # 12:04 call identifier

      #needed on request, response, fault

      uint32 :alloc_hint, initial_value: -> {80} # 16:04 allocation hint
      uint16 :p_cont_id, initial_value: 0 # 20:02 pres context, i.e. data rep
      uint16 :opnum, initial_value: 15 # 22:02 operation #within the interface

      # optional field for request, only present if the PFC_OBJECT_UUID field is non-zero

      net_share_enum_all :stub, value: -> { RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.new(server_unc: host) }
      #string :object, initial_value: -> {stubdata(host)}
      #string :object, initial_value: -> {'010000000f000000000000000f0000003100370032002e00310036002e003100340039002e00310036003800000000000100000001000000010000000000000000000000ffffffff0100000000000000'.hex}

      # stub data, 8-octet aligned

      # optional authentication verifier
      # following fields present iff auth_length != 0 */

      #auth_verifier_co_t   auth_verifier # xx:yy
    end
  end
end
