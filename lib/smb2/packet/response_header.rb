require 'smb2/packet'

class Smb2::Packet
  # A response header, largely copy-pasta'd from the request header.
  # @todo DRY
  class ResponseHeader < Smb2::Packet
    string   :magic,         32, default: "\xfeSMB".force_encoding("binary")
    unsigned :header_len,    16, default: 64
    unsigned :credit_charge, 16, default: 1

    unsigned :nt_status,     32

    unsigned :command,       16

    unsigned :credits_requested, 16
    unsigned :flags,         32
    unsigned :chain_offset,  32
    unsigned :command_seq,   64
    unsigned :process_id,    32
    unsigned :tree_id,       32
    unsigned :session_id,    64

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
