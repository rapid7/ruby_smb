module RubySMB
  # A packet parsing and manipulation library for the SMB2 protocol
  #
  # [[MS-SMB2] Server Message Block (SMB) Protocol Versions 2 and 3](https://msdn.microsoft.com/en-us/library/cc246482.aspx)
  module SMB2
    # Protocol ID value. Translates to \xFESMB
    SMB2_PROTOCOL_ID = 0xFE534D42
    # Wildcard revision, see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5
    SMB2_WILDCARD_REVISION = 0x02ff

    # Channel types, see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/320f04f3-1b28-45cd-aaa1-9e5aed810dca
    SMB2_CHANNEL_NONE = 0
    SMB2_CHANNEL_RDMA_V1 = 1
    SMB2_CHANNEL_RDMA_V1_INVALIDATE = 2

    require 'ruby_smb/smb2/info_type'
    require 'ruby_smb/smb2/commands'
    require 'ruby_smb/smb2/create_context'
    require 'ruby_smb/smb2/bit_field'
    require 'ruby_smb/smb2/smb2_header'
    require 'ruby_smb/smb2/packet'
    require 'ruby_smb/smb2/tree'
    require 'ruby_smb/smb2/file'
    require 'ruby_smb/smb2/pipe'
  end
end
