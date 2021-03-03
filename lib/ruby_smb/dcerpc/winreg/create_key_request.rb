module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegCreateKey Request Packet as defined in
      # [3.1.5.7 BaseRegCreateKey (Opnum 6)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/c7186ae2-1c82-45e9-933b-97d9873657e8)
      class CreateKeyRequest < BinData::Record
        # Options:
        # bitwise OR of one of the key types (REG_KEY_TYPE_*), and any or none
        # of the other options:
        #
        # This key is not volatile. The key and all its values MUST be
        # persisted to the backing store and is preserved when the registry
        # server loses context due to a computer restart, reboot, or shut down
        # process.
        REG_KEY_TYPE_NON_VOLATILE  = 0x00000000
        # This key is volatile. The key with all its subkeys and values MUST
        # NOT be preserved when the registry server loses context due to a
        # computer restart, reboot, or shut down process.
        REG_KEY_TYPE_VOLATILE      = 0x00000001
        # This key is a symbolic link to another key.
        REG_KEY_TYPE_SYMLINK       = 0x00000002
        # Indicates that the caller wishes to assert its backup and/or restore
        # privileges.
        REG_OPTION_BACKUP_RESTORE  = 0x00000004
        # Indicates that the caller wishes to open the targeted symlink source
        # rather than the symlink target.
        REG_OPTION_OPEN_LINK       = 0x00000008
        # Indicates that the caller wishes to disable limited user access
        # virtualization for this operation.
        REG_OPTION_DONT_VIRTUALIZE = 0x00000010


        # Create disposition:
        # The key did not exist and was created.
        REG_CREATED_NEW_KEY     = 0x00000001
        # The key already existed and was opened without being changed.
        REG_OPENED_EXISTING_KEY = 0x00000002

        attr_reader :opnum

        endian :little

        rpc_hkey                 :hkey
        rrp_unicode_string       :lp_sub_key
        string                   :pad1, length: -> { pad_length(self.lp_sub_key) }
        rrp_unicode_string       :lp_class
        string                   :pad2, length: -> { pad_length(self.lp_class) }
        uint32                   :dw_options
        regsam                   :sam_desired
        prpc_security_attributes :lp_security_attributes
        string                   :pad3, length: -> { pad_length(self.lp_security_attributes) }
        uint32_ptr               :lpdw_disposition

        def initialize_instance
          super
          @opnum = REG_CREATE_KEY
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

