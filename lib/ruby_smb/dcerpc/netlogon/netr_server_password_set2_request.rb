require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # []()
      class NlTrustPassword < BinData::Record
        endian :little
        fix_array :buffer, type: :wide_char, initial_length: 256
        uint32    :passwd_length
      end

      # [3.5.4.4.5 NetrServerPasswordSet2 (Opnum 30)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/14b020a8-0bcf-4af5-ab72-cc92bc6b1d81)
      class NetrServerPasswordSet2Request < BinData::Record
        attr_reader :opnum

        endian :little

        logonsrv_handle              :primary_name
        string                       :pad1, length: -> { pad_length(self.primary_name) }
        conf_var_wide_string         :account_name
        netlogon_secure_channel_type :secure_channel_type
        string                       :pad2, length: -> { pad_length(self.secure_channel_type) }
        conf_var_wide_string         :computer_name
        string                       :pad3, length: -> { pad_length(self.computer_name) }
        netlogon_authenticator       :authenticator
        # TODO: check this, it should be a pointer to an NL_TRUST_PASSWORD structure
        nl_trust_password            :clear_new_password
        #fix_array                    :clear_new_password, type: :uint8, initial_length: 516 # this is an encrypted NL_TRUST_PASSWORD

        def initialize_instance
          super
          @opnum = Netlogon::NETR_SERVER_PASSWORD_SET2
        end

        # Determines the correct length for the padding, so that the next
        # field is 4-byte aligned.
        def pad_length(prev_element)
          offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
          (4 - offset) % 4
        end

        def assign(val)
          val = val.bytes if val.is_a?(String)
          super(val)
        end
      end
    end
  end
end
