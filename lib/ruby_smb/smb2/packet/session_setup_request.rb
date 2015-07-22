require 'ruby_smb/smb2/packet'

# [Section 2.2.5 SMB2 SESSION_SETUP Request](https://msdn.microsoft.com/en-us/library/cc246563.aspx)
class Smb2::Packet::SessionSetupRequest < Smb2::Packet::Request

  # A key in {Smb2::COMMANDS}
  COMMAND = :SESSION_SETUP

  unsigned :struct_size,   16, default: 25
  unsigned :flags,          8, default: 0x00
  # @see Packet::SECURITY_MODES
  unsigned :security_mode,  8

  # The documentation says the only flag defined for capabilities is
  # `SMB2_GLOBAL_CAP_DFS` (0x1), however Wireshark also includes these
  # values:
  #  - 0x01 DFS
  #  - 0x02 LEASING
  #  - 0x04 LARGE MTU
  #  - 0x08 MULTI CHANNEL
  #  - 0x10 PERSISTENT HANDLES
  #  - 0x20 DIRECTORY LEASING
  #  - 0x40 ENCRYPTION
  unsigned :capabilities,  32, default: 0x0000_0001
  unsigned :channel,       32, default: 0

  data_buffer :security_blob

  unsigned :previous_session_id, 64

  # @todo Consider giving this an NTLM class so bit-struct will instantiate
  # for us automatically
  rest :buffer

  FLAGS = {
    SESSION_BINDING_REQUEST: 0x0000_0001
  }.freeze
  FLAG_NAMES = FLAGS.keys
end
