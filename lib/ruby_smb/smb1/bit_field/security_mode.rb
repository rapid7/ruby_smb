module RubySMB
  module SMB1
    module BitField
      # The SecurityMode bit-field for a NegotiateResponse as defined in
      # [2.2.4.52.2 Response](https://msdn.microsoft.com/en-us/library/ee441946.aspx)
      class SecurityMode < BinData::Record
        endian :little
        bit1    :user_security,                 :label => 'User Level Access'
        bit1    :encrypt_passwords,             :label => 'Encrypted Password'
        bit1    :security_signatures_enabled,   :label => 'Signatures Enabled'
        bit1    :security_signatures_required,  :label => 'Signatures Required'
        resume_byte_alignment
      end
    end
  end
end