module RubySMB
  module Dcerpc
    module Samr
      # [2.2.3.5 DOMAIN_PASSWORD_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/0ae356d8-c220-4706-846e-ebbdc6fabdcb)
      class SamprDomainPasswordInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint16 :min_password_length
        ndr_uint16 :password_history_length
        ndr_uint32 :password_properties
        ndr_int64  :max_password_age
        ndr_int64  :min_password_age
      end

      # [2.2.3.12 SAMPR_DOMAIN_OEM_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/7cbb7ff0-e593-440d-8341-a3435195cdf1)
      class SamprDomainOemInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        rpc_unicode_string :oem_information
      end

      # [2.2.3.7 DOMAIN_SERVER_ROLE_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/cb0e586a-29c8-49b2-8ced-c273a7476c22)
      class SamprDomainServerRoleInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint16 :domain_server_role
      end

      # [2.2.3.15 SAMPR_DOMAIN_LOCKOUT_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/c9d789ed-c54a-4450-be56-251e627e1f52)
      class SamprDomainLockoutInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint64  :lockout_duration
        ndr_uint64  :lockout_observation_window
        ndr_uint16  :lockout_threshold
      end

      # [2.2.3.10 SAMPR_DOMAIN_GENERAL_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/85973e1c-96f2-4c80-8135-b24d74ad7794)
      class SamprDomainGeneralInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_int64          :force_logoff
        rpc_unicode_string :oem_information
        rpc_unicode_string :domain_name
        rpc_unicode_string :replica_source_node_name
        ndr_int64          :domain_modified_count
        ndr_uint32         :domain_server_state
        ndr_uint32         :domain_server_role
        ndr_uint8          :uas_compatibility_required
        ndr_uint32         :user_count
        ndr_uint32         :group_count
        ndr_uint32         :alias_count
      end

      # [2.2.3.6 DOMAIN_LOGOFF_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6fb0bbea-888c-4353-b5f8-75e7862344be)
      class SamprDomainLogoffInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_int64  :force_logoff
      end

      # [2.2.3.13 SAMPR_DOMAIN_NAME_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/5131d2c0-04c7-4c1b-8fd5-0b0b6cfa6c24)
      class SamprDomainNameInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        rpc_unicode_string :domain_name
      end

      # [2.2.3.8 DOMAIN_MODIFIED_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/5131d2c0-04c7-4c1b-8fd5-0b0b6cfa6c24)
      class SamprDomainModifiedInformation < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_int64 :domain_modified_count
        ndr_int64 :creation_time
      end

      # [2.2.3.9 DOMAIN_MODIFIED_INFORMATION2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/47eea81b-5fee-4925-b5c1-fc594dcc8dff)
      class SamprDomainModifiedInformation2 < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_int64 :domain_modified_count
        ndr_int64 :creation_time
        ndr_int64 :modified_count_at_last_promotion
      end

      # [2.2.3.17 SAMPR_DOMAIN_INFO_BUFFER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/1adc2142-dbb8-4554-aa24-010c713698bf)
      class SamprDomainInfoBuffer < BinData::Record
        default_parameters byte_align: 4
        endian :little

        uint16 :info_class
        skip   length: 2

        choice :buffer, selection: :info_class do
          sampr_domain_password_information    DOMAIN_PASSWORD_INFORMATION
          sampr_domain_oem_information         DOMAIN_OEM_INFORMATION
          sampr_domain_server_role_information DOMAIN_SERVER_ROLE_INFORMATION
          sampr_domain_lockout_information     DOMAIN_LOCKOUT_INFORMATION
          sampr_domain_logoff_information      DOMAIN_LOGOFF_INFORMATION
          sampr_domain_general_information     DOMAIN_GENERAL_INFORMATION
          sampr_domain_name_information        DOMAIN_NAME_INFORMATION
          sampr_domain_modified_information    DOMAIN_MODIFIED_INFORMATION
          sampr_domain_modified_information2   DOMAIN_MODIFIED_INFORMATION2
          # DOMAIN_REPLICATION_INFORMATION
          # DOMAIN_GENERAL_INFORMATION2
          # DOMAIN_STATE_INFORMATION
        end
      end

      class PsamprDomainInfoBuffer < SamprDomainInfoBuffer
        extend Ndr::PointerClassPlugin
      end
    end
  end
end
