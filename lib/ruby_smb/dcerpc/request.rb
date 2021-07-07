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
          create_key_request     RubySMB::Dcerpc::Winreg::REG_CREATE_KEY
          save_key_request       RubySMB::Dcerpc::Winreg::REG_SAVE_KEY
          string                 :default
        end
        choice 'Netlogon', selection: -> { opnum } do
          netr_server_authenticate3_request RubySMB::Dcerpc::Netlogon::NETR_SERVER_AUTHENTICATE3
          netr_server_password_set2_request RubySMB::Dcerpc::Netlogon::NETR_SERVER_PASSWORD_SET2
          netr_server_req_challenge_request RubySMB::Dcerpc::Netlogon::NETR_SERVER_REQ_CHALLENGE
          string                            :default
        end
        choice 'Srvsvc', selection: -> { opnum } do
          net_share_enum_all_request RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL
          string             :default
        end
        choice 'Svcctl', selection: -> { opnum } do
          open_sc_manager_w_request       RubySMB::Dcerpc::Svcctl::OPEN_SC_MANAGER_W
          open_service_w_request          RubySMB::Dcerpc::Svcctl::OPEN_SERVICE_W
          query_service_status_request    RubySMB::Dcerpc::Svcctl::QUERY_SERVICE_STATUS
          query_service_config_w_request  RubySMB::Dcerpc::Svcctl::QUERY_SERVICE_CONFIG_W
          change_service_config_w_request RubySMB::Dcerpc::Svcctl::CHANGE_SERVICE_CONFIG_W
          start_service_w_request         RubySMB::Dcerpc::Svcctl::START_SERVICE_W
          control_service_request         RubySMB::Dcerpc::Svcctl::CONTROL_SERVICE
          close_service_handle_request    RubySMB::Dcerpc::Svcctl::CLOSE_SERVICE_HANDLE
          string                          :default
        end
        choice 'Samr', selection: -> { opnum } do
          samr_connect_request                     RubySMB::Dcerpc::Samr::SAMR_CONNECT
          samr_lookup_domain_in_sam_server_request RubySMB::Dcerpc::Samr::SAMR_LOOKUP_DOMAIN_IN_SAM_SERVER
          samr_open_domain_request                 RubySMB::Dcerpc::Samr::SAMR_OPEN_DOMAIN
          samr_enumerate_users_in_domain_request   RubySMB::Dcerpc::Samr::SAMR_ENUMERATE_USERS_IN_DOMAIN
          samr_rid_to_sid_request                  RubySMB::Dcerpc::Samr::SAMR_RID_TO_SID
          string                                   :default
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
