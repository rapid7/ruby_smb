module RubySMB
  module Dcerpc
    module Samr
      # [2.2.3.5 DOMAIN_PASSWORD_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/0ae356d8-c220-4706-846e-ebbdc6fabdcb)
      class SamprDomainPasswordInformation < BinData::Record
        endian :little

        uint16 :min_password_length
        uint16 :password_history_length
        uint32 :password_properties
        int64  :max_password_age
        int64  :min_password_age
      end

      # [2.2.3.12 SAMPR_DOMAIN_OEM_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/7cbb7ff0-e593-440d-8341-a3435195cdf1)
      class SamprDomainOemInformation < BinData::Record
        endian :little

        rpc_unicode_string :oem_information
      end

      # [2.2.3.7 DOMAIN_SERVER_ROLE_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/cb0e586a-29c8-49b2-8ced-c273a7476c22)
      class SamprDomainServerRoleInformation < BinData::Record
        endian :little

        uint16 :domain_server_role
      end

      # [2.2.3.15 SAMPR_DOMAIN_LOCKOUT_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/c9d789ed-c54a-4450-be56-251e627e1f52)
      class SamprDomainLockoutInformation < BinData::Record
        endian :little

        uint64  :lockout_duration
        uint64  :lockout_observation_window
        uint16  :lockout_threshold
      end

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
        end
      end

      class PsamprDomainInfoBuffer < SamprDomainInfoBuffer
        extend Ndr::PointerClassPlugin
      end
    end
  end
end
