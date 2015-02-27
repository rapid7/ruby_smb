# Implements [Section 2.2.3 SMB2 NEGOTIATE Request](https://msdn.microsoft.com/en-us/library/cc246543.aspx)
class Smb2::Packet::NegotiateRequest < Smb2::Packet::Generic
  nest :header, Smb2::Packet::RequestHeader
  unsigned :struct_size, 16, default: 36
  unsigned :dialect_count, 16, default: 1
  unsigned :security_mode, 16
  unsigned :reserved, 16
  unsigned :capabilities, 32, default: 0x0000_0001
  string :client_guid, 128 # 16 bytes
  unsigned :client_start_time, 64, default: 0

  # Just 2.02 for now. XXX Update dialect_count if you add anything here
  # XXX :default doesn't do anything at all on rest fields
  rest :dialects #, default: "\x02\x02"
end


