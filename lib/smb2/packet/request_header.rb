require 'smb2/packet'

class Smb2::Packet
  # A request header
  #
  #     0                   1                   2                   3
  #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |               magic: "\xFE\x53\x4d\x42"                       |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |        header_len             |         credit_charge         |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |        channel_seq            |         reserved (0)          |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |        command                |      credits_requested        |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |                             flags                             |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |                          chain_offset                         |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |                        command_sequence                       |
  #    |                                                               |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |                           process_id                          |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |                            tree_id                            |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |                           session_id                          |
  #    |                                                               |
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #    |                      signature (16 bytes)                     |
  #    *                                                               *
  #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  class RequestHeader < Smb2::Packet
    string   :magic,         32, default: "\xfeSMB".force_encoding('binary')
    unsigned :header_len,    16, default: 64, endian: 'little'
    unsigned :credit_charge, 16, default: 1, endian: 'little'

    # Here the response would have a 32-bit nt_response. Instead we have 2
    # 16-bit values.
    unsigned :channel_seq,   16, endian: 'little'
    unsigned :reserved,      16, default: 0, endian: 'little'

    unsigned :command,       16, endian: 'little'

    unsigned :credits_requested, 16, endian: 'little'
    unsigned :flags,         32, endian: 'little'
    unsigned :chain_offset,  32, endian: 'little'
    unsigned :command_seq,   64, endian: 'little'
    unsigned :process_id,    32, endian: 'little'
    unsigned :tree_id,       32, endian: 'little'
    unsigned :session_id,    64, endian: 'little'

    # 16 bytes
    string :signature,       (8*16)

  end
end

