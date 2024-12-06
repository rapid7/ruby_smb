module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.10.3 SamrUnicodeChangePasswordUser2 (Opnum 55)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880)
      class SamrUnicodeChangePasswordUser2Request < BinData::Record
        attr_reader :opnum

        endian :little

        prpc_unicode_string               :server_name
        rpc_unicode_string                :user_name
        psampr_encrypted_user_password    :new_password_encrypted_with_old_nt
        pencrypted_nt_owf_password        :old_nt_owf_password_encrypted_with_new_nt
        ndr_uint8                         :lm_present
        psampr_encrypted_user_password    :new_password_encrypted_with_old_lm
        pencrypted_nt_owf_password        :old_lm_owf_password_encrypted_with_new_nt

        def initialize_instance
          super
          @opnum = SAMR_UNICODE_CHANGE_PASSWORD_USER2
        end
      end

    end
  end
end
