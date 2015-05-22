require 'smb2/packet'

class Smb2::Packet
  # A request header, described by this lovely 32-bit wide ASCII diagram:
  #
  # ```
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
  # ```
  class RequestHeader < Smb2::Packet
    # The magic header value, always `\xFE\x53\x4d\x42`
    string :magic, 32, default: "\xfeSMB".force_encoding("binary")
    # Length of the SMB2 header, including itself and the magic. Should
    # always be 64.
    unsigned :header_len, 16, default: 64

    unsigned :credit_charge, 16, default: 1

    # Here the response would have a 32-bit `nt_status`. Instead we have 2
    # 16-bit values.
    unsigned :channel_seq, 16
    unsigned :reserved, 16, default: 0

    # The task this packet is meant to perform. Should be one of the values
    # from {Smb2::COMMANDS}
    unsigned :command, 16

    unsigned :credits_requested, 16, default: 31
    unsigned :flags, 32
    # Called "NextCommand" in the Microsoft documentation
    #
    # > NextCommand (4 bytes): For a compounded request, this field MUST be
    #   set to the offset, in bytes, from the beginning of this SMB2 header to
    #   the start of the subsequent 8-byte aligned SMB2 header. If this is not
    #   a compounded request, or this is the last header in a compounded
    #   request, this value MUST be 0.
    unsigned :chain_offset, 32
    unsigned :command_seq, 64
    unsigned :process_id, 32, default: 0x0000_feff
    unsigned :tree_id, 32
    unsigned :session_id, 64

    # 16 bytes
    string :signature, (8 * 16)

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
