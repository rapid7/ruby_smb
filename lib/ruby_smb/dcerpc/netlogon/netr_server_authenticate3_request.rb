require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Netlogon

      # [3.5.4.4.2 NetrServerAuthenticate3 (Opnum 26)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/3a9ed16f-8014-45ae-80af-c0ecb06e2db9)
      class NetrServerAuthenticate3Request < BinData::Record
        attr_reader :opnum

        endian :little

        logonsrv_handle              :primary_name
        string                       :pad1, length: -> { pad_length(self.primary_name) }
        ndr_conf_var_wide_stringz    :account_name
        netlogon_secure_channel_type :secure_channel_type
        string                       :pad2, length: -> { pad_length(self.secure_channel_type) }
        ndr_conf_var_wide_stringz    :computer_name
        netlogon_credential          :client_credential
        string                       :pad3, length: -> { pad_length(self.client_credential) }
        uint32                       :flags

        def initialize_instance
          super
          @opnum = NETR_SERVER_AUTHENTICATE3
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
