require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # [3.5.4.4.5 NetrServerPasswordSet2 (Opnum 30)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/14b020a8-0bcf-4af5-ab72-cc92bc6b1d81)
      class NetrServerPasswordSet2Request < BinData::Record
        attr_reader :opnum

        endian :little

        logonsrv_handle              :primary_name
        string                       :pad1, length: -> { pad_length(self.primary_name) }
        ndr_conf_var_wide_stringz    :account_name
        netlogon_secure_channel_type :secure_channel_type
        string                       :pad2, length: -> { pad_length(self.secure_channel_type) }
        ndr_conf_var_wide_stringz    :computer_name
        string                       :pad3, length: -> { pad_length(self.computer_name) }
        netlogon_authenticator       :authenticator
        ndr_fixed_byte_array         :clear_new_password, initial_length: 516 # this is an encrypted NL_TRUST_PASSWORD

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
      end
    end
  end
end
