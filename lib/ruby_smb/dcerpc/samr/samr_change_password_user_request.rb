module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.10.1 SamrChangePasswordUser (Opnum 38)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
      class SamrChangePasswordUserRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle                      :user_handle
        ndr_uint8                         :lm_present
        pencrypted_nt_owf_password        :old_lm_encrypted_with_new_lm
        pencrypted_nt_owf_password        :new_lm_encrypted_with_old_lm
        ndr_uint8                         :nt_present
        pencrypted_nt_owf_password        :old_nt_encrypted_with_new_nt
        pencrypted_nt_owf_password        :new_nt_encrypted_with_old_nt
        ndr_uint8                         :nt_cross_encryption_present
        pencrypted_nt_owf_password        :new_nt_encrypted_with_new_nt
        ndr_uint8                         :lm_cross_encryption_present
        pencrypted_nt_owf_password        :new_lm_encrypted_with_new_nt

        def initialize_instance
          super
          @opnum = SAMR_CHANGE_PASSWORD_USER
        end
      end

    end
  end
end
