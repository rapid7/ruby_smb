require 'smb2/packet'

class Smb2::Packet
  # A response header, largely copy-pasta'd from the request header.
  # @todo DRY
  class ResponseHeader < Smb2::Packet
    string   :magic,         32, default: "\xfeSMB".b
    unsigned :header_len,    16, default: 64, endian: 'little'
    unsigned :credit_charge, 16, default: 1, endian: 'little'

    unsigned :nt_status,     32, endian: 'little'

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

    FLAGS = {
      REPLAY:   0x0200_0000,
      DFS:      0x0100_0000,
      SIGNING:  0x0000_0008,
      CHAINED:  0x0000_0004,
      ASYNC:    0x0000_0002,
      RESPONSE: 0x0000_0001,
    }.freeze

    FLAG_NAMES = FLAGS.keys
  end
end

