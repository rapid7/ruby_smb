require 'ruby_smb/smb2/packet'

# [[MS-SMB2] 2.2.4 SMB2 NEGOTIATE Response](https://msdn.microsoft.com/en-us/library/cc246561.aspx)
class RubySMB::SMB2::Packet::NegotiateResponse < RubySMB::SMB2::Packet::Response
  COMMAND = :NEGOTIATE

  unsigned :struct_size, 16, default: 65
  unsigned :security_mode, 16
  unsigned :dialect_revision, 16
  unsigned :reserved, 16
  string :server_guid, 16 * 8 # 16 bytes
  unsigned :capabilities,  32, default: 0x0000_0001
  unsigned :max_transaction_size, 32
  unsigned :max_read_size, 32
  unsigned :max_write_size, 32
  unsigned :system_time, 64
  unsigned :server_start_time, 64
  data_buffer :security_blob
  unsigned :reserved2, 32

  rest :buffer
end
