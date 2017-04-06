module RubySMB
  module SMB1
    module BitField
      require 'ruby_smb/smb1/bit_field/header_flags'
      require 'ruby_smb/smb1/bit_field/header_flags2'
      require 'ruby_smb/smb1/bit_field/security_mode'
      require 'ruby_smb/smb1/bit_field/capabilities'
      require 'ruby_smb/smb1/bit_field/tree_connect_flags'
      require 'ruby_smb/smb1/bit_field/optional_support'
      require 'ruby_smb/smb1/bit_field/directory_access_mask'
      require 'ruby_smb/smb1/bit_field/file_access_mask'
    end
  end
end
