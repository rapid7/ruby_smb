require 'smb2/packet'

class Smb2::Packet

  class SessionSetupResponse < Smb2::Packet
    nest :header, ResponseHeader
    unsigned :struct_size,          16, endian: 'little'
    unsigned :flags, 16, endian: 'little'
    data_buffer :security_blob

    rest :buffer

    FLAGS = {
      NULL_SESSION: 0x0000_0010,
      GUEST_SESSION: 0x0000_0001
    }.freeze

    FLAG_NAMES = FLAGS.keys

  end

end

