require 'ruby_smb/dcerpc/ndr'
require 'ruby_smb/dcerpc/rrp_rpc_unicode_string'
require 'ruby_smb/dcerpc/samr/rpc_sid'
require 'ruby_smb/dcerpc/uuid'

module RubySMB
  module Dcerpc
    module Lsarpc

      # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dssp/6f843846-2494-4d49-b715-2f181317dd34
      UUID = '12345778-1234-abcd-ef00-0123456789ab'.freeze
      VER_MAJOR = 0
      VER_MINOR = 0

      # OPNUMS
      LSAR_CLOSE_HANDLE               = 0
      LSAR_OPEN_POLICY                = 6
      LSAR_QUERY_INFORMATION_POLICY   = 7
      LSAR_LOOKUP_SIDS                = 15
      LSAR_OPEN_POLICY2               = 44
      LSAR_QUERY_INFORMATION_POLICY2  = 46

      ################
      # ACCESS_MASK Values

      # [2.2.1.1 ACCESS_MASK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/7aeb7f17-0a6e-4f04-ac7e-7b1363cf9ecf)
      # [2.4.3 ACCESS_MASK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b)
      DELETE                 = 0x00010000
      READ_CONTROL           = 0x00020000
      WRITE_DACL             = 0x00040000
      WRITE_OWNER            = 0x00040000
      SYNCHRONIZE            = 0x00100000
      ACCESS_SYSTEM_SECURITY = 0x01000000
      MAXIMUM_ALLOWED        = 0x02000000
      GENERIC_ALL            = 0x10000000
      GENERIC_EXECUTE        = 0x20000000
      GENERIC_WRITE          = 0x40000000
      GENERIC_READ           = 0x80000000

      ################
      # SECURITY_DESCRIPTOR_CONTROL

      # [SECURITY_DESCRIPTOR_CONTROL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control)
      # [SECURITY_DESCRIPTOR_CONTROL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/security-descriptor-control)
      SE_OWNER_DEFAULTED       = 0x0001
      SE_GROUP_DEFAULTED       = 0x0002
      SE_DACL_PRESENT          = 0x0004
      SE_DACL_DEFAULTED        = 0x0008
      SE_SACL_PRESENT          = 0x0010
      SE_SACL_DEFAULTED        = 0x0020
      SE_DACL_UNTRUSTED        = 0x0040
      SE_SERVER_SECURITY       = 0x0080
      SE_DACL_AUTO_INHERIT_REQ = 0x0100
      SE_SACL_AUTO_INHERIT_REQ = 0x0200
      SE_DACL_AUTO_INHERITED   = 0x0400
      SE_SACL_AUTO_INHERITED   = 0x0800
      SE_DACL_PROTECTED        = 0x1000
      SE_SACL_PROTECTED        = 0x2000
      SE_RM_CONTROL_VALID      = 0x4000
      SE_SELF_RELATIVE         = 0x8000

      # [2.2.3.5 SECURITY_IMPERSONATION_LEVEL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/720cea10-cee2-4c45-9084-c6fa7d67d18d)
      SECURITY_ANONYMOUS      = 0x0000
      SECURITY_IDENTIFICATION = 0x0001
      SECURITY_IMPERSONATION  = 0x0002
      SECURITY_DELEGATION     = 0x0003

      # [2.2.3.6 SECURITY_CONTEXT_TRACKING_MODE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/6bb42770-b924-41ff-8a57-83e37b8b7797)
      SECURITY_CONTEXT_CLIENT_SNAPSHOT    = 0x00
      SECURITY_CONTEXT_CONTINUOUS_UPDATES = 0x01

      # [2.2.4.1 POLICY_INFORMATION_CLASS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/9ce0bb37-fc6c-4230-b109-7e1881660b83)
      POLICY_AUDIT_LOG_INFORMATION            = 1
      POLICY_AUDIT_EVENTS_INFORMATION         = 2
      POLICY_PRIMARY_DOMAIN_INFORMATION       = 3
      POLICY_PD_ACCOUNT_INFORMATION           = 4
      POLICY_ACCOUNT_DOMAIN_INFORMATION       = 5
      POLICY_LSA_SERVER_ROLE_INFORMATION      = 6
      POLICY_REPLICA_SOURCE_INFORMATION       = 7
      POLICY_INFORMATION_NOT_USED_ON_WIRE     = 8
      POLICY_MODIFICATION_INFORMATION         = 9
      POLICY_AUDIT_FULL_SET_INFORMATION       = 10
      POLICY_AUDIT_FULL_QUERY_INFORMATION     = 11
      POLICY_DNS_DOMAIN_INFORMATION           = 12
      POLICY_DNS_DOMAIN_INFORMATION_INT       = 13
      POLICY_LOCAL_ACCOUNT_DOMAIN_INFORMATION = 14
      POLICY_MACHINE_ACCOUNT_INFORMATION      = 15
      POLICY_LAST_ENTRY                       = 16

      # [2.2.4.8 POLICY_LSA_SERVER_ROLE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/620010b4-b439-4d46-893a-cb67246de5fc)
      POLICY_SERVER_ROLE_BACKUP  = 2
      POLICY_SERVER_ROLE_PRIMARY = 3

      # [2.2.16 LSAP_LOOKUP_LEVEL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/9d1166cc-bcfd-4e22-a8ac-f55eae57c99f)
      LSAP_LOOKUP_WKSTA                    = 1
      LSAP_LOOKUP_PDC                      = 2
      LSAP_LOOKUP_TDL                      = 3
      LSAP_LOOKUP_GC                       = 4
      LSAP_LOOKUP_XFOREST_REFERRAL         = 5
      LSAP_LOOKUP_XFOREST_RESOLVE          = 6
      LSAP_LOOKUP_RODC_REFERRAL_TO_FULL_DC = 7

      # [2.2.13 SID_NAME_USE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/171e9a87-8e01-4bd8-a35e-3468128c8fc4)
      SID_TYPE_USER            = 1
      SID_TYPE_GROUP           = 2
      SID_TYPE_DOMAIN          = 3
      SID_TYPE_ALIAS           = 4
      SID_TYPE_WELLKNOWN_GROUP = 5
      SID_TYPE_DELETED_ACCOUNT = 6
      SID_TYPE_INVALID         = 7
      SID_TYPE_UNKNOWN         = 8
      SID_TYPE_COMPUTER        = 9
      SID_TYPE_LABEL           = 10

      # [2.2.2.1 LSAPR_HANDLE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/0d093105-e8c8-45f7-a79d-182aafd60c6e)
      class LsaprHandle < Ndr::NdrContextHandle; end

      class LsaprHandlePtr < LsaprHandle
        extend Ndr::PointerClassPlugin
      end

      # [2.2.3.2 LSAPR_ACL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/a9a03a85-5b08-4bb5-81c9-2c68751693ac)
      class LsaprAcl < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint8      :acl_revision
        ndr_uint8      :sbz1
        ndr_uint16     :acl_size
        ndr_conf_array :dummy1, type: :ndr_char
      end

      class LsaprAclPtr < LsaprAcl
        extend Ndr::PointerClassPlugin
      end

      # [2.2.3.3 SECURITY_DESCRIPTOR_CONTROL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/c704a67c-9836-41d9-9b18-acd596cc884e)
      class LsaprSecurityDescriptorControl < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint16 :security_descriptor_control
      end

      class LsaprSecurityDescriptorControlPtr < LsaprSecurityDescriptorControl
        extend Ndr::PointerClassPlugin
      end

      # [2.2.5 LSAPR_SECURITY_DESCRIPTOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/8494008f-0bfb-45b8-bb6c-e32dd7f18e3d)
      class LsaprSecurityDescriptor < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint8                         :revision
        ndr_uint8                         :sbz1
        lsapr_security_descriptor_control :control
        prpc_sid                          :owner
        prpc_sid                          :group
        lsapr_acl_ptr                     :sacl
        lsapr_acl_ptr                     :dacl
      end

      class LsaprSecurityDescriptorPtr < LsaprSecurityDescriptor
        extend Ndr::PointerClassPlugin
      end

      # [2.2.3.5 SECURITY_IMPERSONATION_LEVEL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/720cea10-cee2-4c45-9084-c6fa7d67d18d)
      class SecurityImpersonationLevel < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32 :level # This is SECURITY_IMPERSONATION_LEVEL, type 'enum' -> uint32
      end

      class SecurityImpersonationLevelPtr < SecurityImpersonationLevel
        extend Ndr::PointerClassPlugin
      end

      # [2.2.3.6 SECURITY_CONTEXT_TRACKING_MODE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/6bb42770-b924-41ff-8a57-83e37b8b7797)
      class LsaprSecurityContextTrackingMode < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint8 :security_context_tracking_mode
      end

      class LsaprSecurityContextTrackingModePtr < LsaprSecurityContextTrackingMode
        extend Ndr::PointerClassPlugin
      end

      # [2.2.3.7 SECURITY_QUALITY_OF_SERVICE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/0ddf3150-53b5-42a5-b0ec-518bce67738c)
      class SecurityQualityOfService < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32 :len, value: -> { 12 }
        ndr_uint16 :impersonation_level
        ndr_uint8  :security_context_tracking_mode
        ndr_uint8  :effective_only
      end

      class SecurityQualityOfServicePtr < SecurityQualityOfService
        extend Ndr::PointerClassPlugin
      end

      # [2.2.2.4 LSAPR_OBJECT_ATTRIBUTES](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/ad9e183d-6474-4641-a6d9-d3796d2d604b)
      class LsaprObjectAttributes < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32                      :len, value: -> { 24 }
        ndr_char_ptr                    :root_directory
        ndr_wide_stringz_ptr            :object_name
        ndr_uint32                      :attributes
        lsapr_security_descriptor_ptr   :security_descriptor
        security_quality_of_service_ptr :security_quality_of_service
      end

      class LsaprObjectAttributesPtr < LsaprObjectAttributes
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.1 POLICY_INFORMATION_CLASS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/9ce0bb37-fc6c-4230-b109-7e1881660b83)
      class LsaprPolicyInformationClass < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32 :policy_information_class # This is POLICY_INFORMATION_CLASS, type 'enum' -> uint32
      end

      class LsaprPolicyInformationClassPtr < LsaprPolicyInformationClass
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.3 POLICY_AUDIT_LOG_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/3fff1c62-e8b1-4bc8-b18a-3ba6458ec622)
      class LsaprPolicyAuditLogInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32 :audit_log_percent_full
        ndr_uint32 :maximum_log_size
        ndr_uint64 :audit_retention_period
        ndr_uint8  :audit_log_full_shutdown_in_progress
        ndr_uint64 :time_to_shutdown
        ndr_uint32 :next_audit_record_id
      end

      class LsaprPolicyAuditLogInfoPtr < LsaprPolicyAuditLogInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.4 LSAPR_POLICY_AUDIT_EVENTS_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/d00fc364-577d-4ed0-b3a5-952d78b67695)
      class LsaprPolicyAuditEventsInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint8      :auditing_mode
        ndr_uint32_ptr :event_auditing_options
        ndr_uint32     :maximum_audit_event_count
      end

      class LsaprPolicyAuditEventsInfoPtr < LsaprPolicyAuditEventsInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.5 LSAPR_POLICY_PRIMARY_DOM_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/0f3f5d3f-66d2-45a0-8c28-ede86f4cd4a8)
      class LsaprPolicyPrimaryDomInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_wide_string_ptr :name
        prpc_sid            :sid
      end

      class LsaprPolicyPrimaryDomInfoPtr < LsaprPolicyPrimaryDomInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.6 LSAPR_POLICY_ACCOUNT_DOM_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/bfad5424-3e20-43bd-87f6-d35b4253792e)
      class LsaprPolicyAccountDomInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_wide_string_ptr :domain_name
        prpc_sid            :domain_sid
      end

      class LsaprPolicyAccountDomInfoPtr < LsaprPolicyAccountDomInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.7 LSAPR_POLICY_PD_ACCOUNT_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/b04175b3-fedf-4dda-9034-f754a10fe64e)
      class LsaprPolicyPdAccountInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        rpc_unicode_string :name
      end

      class LsaprPolicyPdAccountInfoPtr < LsaprPolicyPdAccountInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.8 POLICY_LSA_SERVER_ROLE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/620010b4-b439-4d46-893a-cb67246de5fc)
      class LsaprPolicyLsaServerRole < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32 :policy_lsa_server_role # This is POLICY_LSA_SERVER_ROLE, type 'enum' -> uint32
      end

      class LsaprPolicyLsaServerRolePtr < LsaprPolicyLsaServerRole
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.9 POLICY_LSA_SERVER_ROLE_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/d37dbc65-04f3-4db8-b40a-4e9dd6c12520)
      class LsaprPolicyLsaServerRoleInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        lsapr_policy_lsa_server_role :lsa_server_role
      end

      class LsaprPolicyLsaServerRoleInfoPtr < LsaprPolicyLsaServerRoleInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.10 LSAPR_POLICY_REPLICA_SRCE_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/fb7df2bb-99e7-402f-8334-24d47e23ec00)
      class LsaprPolicyReplicaSrceInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        rpc_unicode_string :replica_source
        rpc_unicode_string :replica_account_name
      end

      class LsaprPolicyReplicaSrceInfoPtr < LsaprPolicyReplicaSrceInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.11 POLICY_MODIFICATION_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/c80ae9d5-d0c1-4d5c-a0ae-77eae7bfac25)
      class PolicyModificationInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint64 :modified_id
        ndr_uint64 :database_creation_time
      end

      class PolicyModificationInfoPtr < PolicyModificationInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.12 POLICY_AUDIT_FULL_SET_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/3224400e-3c40-4e64-810a-8b11341ba4c6)
      class PolicyAuditFullSetInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint8 :shutdown_on_full
      end

      class PolicyAuditFullSetInfoPtr < PolicyAuditFullSetInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.13 POLICY_AUDIT_FULL_QUERY_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/0ef0845f-f20e-4897-ad29-88c0c07be0f4)
      class PolicyAuditFullQueryInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint8 :shutdown_on_full
        ndr_uint8 :log_is_full
      end

      class PolicyAuditFullQueryInfoPtr < PolicyAuditFullQueryInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.14 LSAPR_POLICY_DNS_DOMAIN_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/3e15a02e-25d3-46aa-9c60-8def03c824d2)
      class LsaprPolicyDnsDomainInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        rpc_unicode_string :name
        rpc_unicode_string :dns_domain_name
        rpc_unicode_string :dns_forest_name
        uuid               :domain_guid
        prpc_sid           :sid
      end

      class LsaprPolicyDnsDomainInfoPtr < LsaprPolicyDnsDomainInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.21 LSAPR_POLICY_MACHINE_ACCT_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/e05c1489-e8c9-4b6c-8b5e-f95d5dd7b1b2)
      class LsaprPolicyMachineAcctInfo < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32 :rid
        prpc_sid   :sid
      end

      class LsaprPolicyMachineAcctInfoPtr < LsaprPolicyMachineAcctInfo
        extend Ndr::PointerClassPlugin
      end

      # [2.2.4.2 LSAPR_POLICY_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/6e63a2c8-5ddb-411a-a253-9c55afc49834)
      class LsaprPolicyInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32 :policy_information_class
        choice :policy_information, selection: -> { policy_information_class }, byte_align: 4 do
          lsapr_policy_audit_log_info_ptr       POLICY_AUDIT_LOG_INFORMATION
          lsapr_policy_audit_events_info_ptr    POLICY_AUDIT_EVENTS_INFORMATION
          lsapr_policy_primary_dom_info_ptr     POLICY_PRIMARY_DOMAIN_INFORMATION
          lsapr_policy_pd_account_info_ptr      POLICY_PD_ACCOUNT_INFORMATION
          lsapr_policy_account_dom_info_ptr     POLICY_ACCOUNT_DOMAIN_INFORMATION
          lsapr_policy_lsa_server_role_info_ptr POLICY_LSA_SERVER_ROLE_INFORMATION
          lsapr_policy_replica_srce_info_ptr    POLICY_REPLICA_SOURCE_INFORMATION
          policy_modification_info_ptr          POLICY_MODIFICATION_INFORMATION
          policy_audit_full_set_info_ptr        POLICY_AUDIT_FULL_SET_INFORMATION
          policy_audit_full_query_info_ptr      POLICY_AUDIT_FULL_QUERY_INFORMATION

          #Note: The lines below have the same output for two different inputs.
          lsapr_policy_dns_domain_info_ptr      POLICY_DNS_DOMAIN_INFORMATION
          lsapr_policy_dns_domain_info_ptr      POLICY_DNS_DOMAIN_INFORMATION_INT

          lsapr_policy_account_dom_info_ptr     POLICY_LOCAL_ACCOUNT_DOMAIN_INFORMATION
          lsapr_policy_machine_acct_info_ptr    POLICY_MACHINE_ACCOUNT_INFORMATION
        end
      end

      class LsaprPolicyInformationPtr < LsaprPolicyInformation
        extend Ndr::PointerClassPlugin
      end

      # [2.2.17 LSAPR_SID_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/f04a771b-c018-4098-81b5-2a819f9b5db8)
      class LsaprSidInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        prpc_sid :sid
      end

      class LsaprSidInformationPtr < LsaprSidInformation
        extend Ndr::PointerClassPlugin
      end

      class LsaprSidInformationArrayPtr < Ndr::NdrConfArray
        default_parameters type: :lsapr_sid_information
        extend Ndr::PointerClassPlugin
      end

      # [2.2.18 LSAPR_SID_ENUM_BUFFER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/1ffb61f0-a4fe-4487-858d-fb709d605855)
      class LsaprSidEnumBuffer < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32                      :num_entries
        lsapr_sid_information_array_ptr :sid_info
      end

      class LsaprSidEnumBufferPtr < LsaprSidEnumBuffer
        extend Ndr::PointerClassPlugin
      end

      # [2.2.11 LSAPR_TRUST_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/b0f34b28-b5da-44aa-a607-99c09e6526e1)
      class LsaprTrustInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        rpc_unicode_string :name
        prpc_sid           :sid
      end

      class LsaprTrustInformationArrayPtr < Ndr::NdrConfArray
        default_parameters type: :lsapr_trust_information
        extend Ndr::PointerClassPlugin
      end

      # [2.2.12 LSAPR_REFERENCED_DOMAIN_LIST](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/3a52af31-247a-4b08-91a0-1d46b2cc49b2)
      class LsaprReferencedDomainList < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32                        :num_entries
        lsapr_trust_information_array_ptr :domains
        ndr_uint32                        :max_entries
      end

      class LsaprReferencedDomainListPtr < LsaprReferencedDomainList
        extend Ndr::PointerClassPlugin
      end

      # [2.2.19 LSAPR_TRANSLATED_NAME](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/52e1ccc1-b57b-4c02-b35f-bd64913ce99b)
      class LsaprTranslatedName < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32         :use
        rpc_unicode_string :name
        ndr_uint32         :domain_index
      end

      class LsaprTranslatedNameArray < Ndr::NdrConfArray
        default_parameters type: :lsapr_translated_name
        extend Ndr::PointerClassPlugin
      end

      class LsaprTranslatedNameArrayPtr < LsaprTranslatedNameArray
        extend Ndr::PointerClassPlugin
      end

      # [2.2.20 LSAPR_TRANSLATED_NAMES](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/ff977eb9-563a-4353-a95f-640e7ee16356)
      class LsaprTranslatedNames < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32                      :num_entries
        lsapr_translated_name_array_ptr :names
      end

      class LsaprTranslatedNamesPtr < LsaprTranslatedNames
        extend Ndr::PointerClassPlugin
      end

      require 'ruby_smb/dcerpc/lsarpc/lsar_open_policy_request'
      require 'ruby_smb/dcerpc/lsarpc/lsar_open_policy_response'
      require 'ruby_smb/dcerpc/lsarpc/lsar_open_policy2_request'
      require 'ruby_smb/dcerpc/lsarpc/lsar_open_policy2_response'
      require 'ruby_smb/dcerpc/lsarpc/lsar_query_information_policy_request'
      require 'ruby_smb/dcerpc/lsarpc/lsar_query_information_policy_response'
      require 'ruby_smb/dcerpc/lsarpc/lsar_query_information_policy2_request'
      require 'ruby_smb/dcerpc/lsarpc/lsar_query_information_policy2_response'
      require 'ruby_smb/dcerpc/lsarpc/lsar_close_handle_request'
      require 'ruby_smb/dcerpc/lsarpc/lsar_close_handle_response'
      require 'ruby_smb/dcerpc/lsarpc/lsar_lookup_sids_request'
      require 'ruby_smb/dcerpc/lsarpc/lsar_lookup_sids_response'

      def lsar_open_policy2(system_name:, object_attributes:, access_mask:)
        lsar_request = LsarOpenPolicy2Request.new(
          system_name: system_name,
          object_attributes: object_attributes,
          access_mask: access_mask
        )
        response = dcerpc_request(lsar_request)
        begin
          lsar_response = LsarOpenPolicy2Response.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading LsarOpenPolicy2Response'
        end
        unless lsar_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::LsarpcError,
                "Error returned while opening policy: "\
                  "#{WindowsError::NTStatus.find_by_retval(lsar_response.error_status.value).join(',')}"
        end
        lsar_response.policy_handle
      end

      def lsar_query_information_policy(policy_handle:, information_class:)
        lsar_request = LsarQueryInformationPolicyRequest.new(
          policy_handle: policy_handle,
          information_class: information_class
        )
        response = dcerpc_request(lsar_request)
        begin
          lsar_response = LsarQueryInformationPolicyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading LsarQueryInformationPolicyResponse'
        end
        unless lsar_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::LsarpcError,
                "Error returned while querying domain information: "\
                  "#{WindowsError::NTStatus.find_by_retval(lsar_response.error_status.value).join(',')}"
        end
        lsar_response.policy_information
      end

      def lsar_query_information_policy2(policy_handle:, information_class:)
        lsar_request = LsarQueryInformationPolicy2Request.new(
          policy_handle: policy_handle,
          information_class: information_class
        )
        response = dcerpc_request(lsar_request)
        begin
          lsar_response = LsarQueryInformationPolicy2Response.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading LsarQueryInformationPolicy2Response'
        end
        unless lsar_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::LsarpcError,
                "Error returned while querying domain information: "\
                  "#{WindowsError::NTStatus.find_by_retval(lsar_response.error_status.value).join(',')}"
        end
        lsar_response.policy_information
      end

      def lsar_close_handle(policy_handle:)
        lsar_request = LsarCloseHandleRequest.new(
          policy_handle: policy_handle
        )
        response = dcerpc_request(lsar_request)
        begin
          lsar_response = LsarCloseHandleResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading LsarCloseHandleResponse'
        end
        unless lsar_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::LsarpcError,
                "Error returned while closing policy handle: "\
                  "#{WindowsError::NTStatus.find_by_retval(lsar_response.error_status.value).join(',')}"
        end
        lsar_response.policy_handle
      end

      def lsar_lookup_sids(policy_handle:, sids:, lookup_level:)
        sid_enum_buffer = { num_entries: sids.count, sid_info: sids.map { |sid| { sid: sid } } }
        lsar_request = LsarLookupSidsRequest.new(
          policy_handle: policy_handle,
          sid_enum_buffer: sid_enum_buffer,
          lookup_level: lookup_level
        )
        response = dcerpc_request(lsar_request)
        begin
          lsar_response = LsarLookupSidsResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading LsarLookupSidsResponse'
        end
        unless lsar_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::LsarpcError,
                "Error returned while looking up SID: "\
                  "#{WindowsError::NTStatus.find_by_retval(lsar_response.error_status.value).join(',')}"
        end
        lsar_response.translated_names[:names].map do |translated_name|
          { name: translated_name[:name][:buffer], type: translated_name[:use] }
        end
      end

    end
  end
end
