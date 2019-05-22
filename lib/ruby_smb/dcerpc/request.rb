module RubySMB
  module Dcerpc
    # The Request PDU as defined in
    # [The request PDU](http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_04_09)
    class Request < BinData::Record
      endian :little

      pdu_header :pdu_header, label: 'PDU header'
      uint32     :alloc_hint, label: 'Allocation hint', initial_value: -> { stub.num_bytes }
      uint16     :p_cont_id,  label: 'Presentation context identification'
      uint16     :opnum,      label: 'Operation Number'
      uuid       :object,     label: 'Object UID', onlyif: -> { pdu_header.pfc_flags.object_uuid == 1 }

      choice :stub, label: 'Stub', selection: -> { @obj.parent.get_parameter(:endpoint) || '' } do
        choice 'Winreg', selection: -> { opnum } do
          open_root_key_request  RubySMB::Dcerpc::Winreg::OPEN_HKCR, opnum: RubySMB::Dcerpc::Winreg::OPEN_HKCR
          open_root_key_request  RubySMB::Dcerpc::Winreg::OPEN_HKCU, opnum: RubySMB::Dcerpc::Winreg::OPEN_HKCU
          open_root_key_request  RubySMB::Dcerpc::Winreg::OPEN_HKLM, opnum: RubySMB::Dcerpc::Winreg::OPEN_HKLM
          open_root_key_request  RubySMB::Dcerpc::Winreg::OPEN_HKPD, opnum: RubySMB::Dcerpc::Winreg::OPEN_HKPD
          open_root_key_request  RubySMB::Dcerpc::Winreg::OPEN_HKU,  opnum: RubySMB::Dcerpc::Winreg::OPEN_HKU
          open_root_key_request  RubySMB::Dcerpc::Winreg::OPEN_HKCC, opnum: RubySMB::Dcerpc::Winreg::OPEN_HKCC
          open_root_key_request  RubySMB::Dcerpc::Winreg::OPEN_HKPT, opnum: RubySMB::Dcerpc::Winreg::OPEN_HKPT
          open_root_key_request  RubySMB::Dcerpc::Winreg::OPEN_HKPN, opnum: RubySMB::Dcerpc::Winreg::OPEN_HKPN
          close_key_request      RubySMB::Dcerpc::Winreg::REG_CLOSE_KEY
          enum_key_request       RubySMB::Dcerpc::Winreg::REG_ENUM_KEY
          enum_value_request     RubySMB::Dcerpc::Winreg::REG_ENUM_VALUE
          open_key_request       RubySMB::Dcerpc::Winreg::REG_OPEN_KEY
          query_info_key_request RubySMB::Dcerpc::Winreg::REG_QUERY_INFO_KEY
          query_value_request    RubySMB::Dcerpc::Winreg::REG_QUERY_VALUE
          string                 :default
        end
        choice 'Srvsvc', selection: -> { opnum } do
          net_share_enum_all RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL, host: -> { host rescue '' }
          string             :default
        end
        string :default
      end

      string :auth_verifier, label: 'Authentication verifier',
        onlyif:      -> { pdu_header.auth_length > 0 },
        read_length: -> { pdu_header.auth_length }

      def initialize_instance
        super
        pdu_header.ptype = RubySMB::Dcerpc::PTypes::REQUEST
      end
    end
  end
end
