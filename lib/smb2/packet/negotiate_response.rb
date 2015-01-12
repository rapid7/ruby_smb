require 'smb2/packet'

class Smb2::Packet

  class NegotiateResponse < Smb2::Packet
    nest :header, ResponseHeader
    unsigned :struct_size, 16, default: 65
    unsigned :security_mode, 16
    unsigned :dialect_revision, 16
    unsigned :reserved, 16
    string :server_guid, 256 # 32 bytes
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

end

