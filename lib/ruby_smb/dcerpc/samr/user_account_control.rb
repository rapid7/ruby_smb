module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.14.2 userAccountControl Mapping Table](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/8a193181-a7a2-49df-a8b1-f689aaa6987c)
      # [Use the UserAccountControl flags to manipulate user account properties](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)
      class UserAccountControl < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian  :little

        bit1 :user_encrypted_text_password_allowed
        bit1 :user_passwd_cant_change
        bit1 :user_passwd_notreqd
        bit1 :user_lockout
        bit1 :user_homedir_required
        bit1 :reserved1
        bit1 :user_account_disabled
        bit1 :user_script
        # byte boundary
        bit2 :reserved3
        bit1 :user_server_trust_account
        bit1 :user_workstation_trust_account
        bit1 :user_interdomain_trust_account
        bit1 :reserved2
        bit1 :user_normal_account
        bit1 :user_temp_duplicate_account
        # byte boundary
        bit1 :user_password_expired
        bit1 :user_dont_require_preauth
        bit1 :user_use_des_key_only
        bit1 :user_not_delegated
        bit1 :user_trusted_for_delegation
        bit1 :user_smartcard_required
        bit1 :user_mns_logon_account
        bit1 :user_dont_expire_passwd
        # byte boundary
        bit6 :reserved4
        bit1 :user_no_auth_data_required
        bit1 :user_trusted_to_authenticate_for_delegation
      end

    end
  end
end
