require 'ruby_smb/smb2/packet'

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
class RubySMB::Smb2::Packet::Request < RubySMB::Smb2::Packet::Generic
  def initialize(*args)
    super
    self.header_flags &= ~RubySMB::Smb2::Packet::HEADER_FLAGS[:RESPONSE]
  end

  def channel_seq
    [nt_status].pack("V").unpack("vv").last
  end

  def channel_seq=(other)
    self.nt_status = (nt_status & 0xffff_0000) + other
  end

  def header_reserved
    [nt_status].pack("V").unpack("vv").first
  end

  def header_reserved=(other)
    self.nt_status = (nt_status & 0x0000_ffff) + (other << 16)
  end
end
