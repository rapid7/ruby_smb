require 'smb2/packet'

class Smb2::Packet

  class SessionSetupRequest < Smb2::Packet
    module SecurityModes
      SIGNING_ENABLED = 0x1
      SIGNING_REQUIRED = 0x2
    end
    nest :header, RequestHeader
    unsigned :struct_size,   16
    unsigned :flags,          8, default: 0x00
    unsigned :security_mode,  8
    unsigned :capabilities,  32, default: 0x0000_0001
    unsigned :channel,       32, default: 0

    data_buffer :security_blob

    unsigned :previous_session_id, 64

    rest :buffer

    FLAGS = {
      SESSION_BINDING_REQUEST: 0x0000_0001
    }.freeze
    FLAG_NAMES = FLAGS.keys

    def initialize(*args)
      super
      self.header.command = Smb2::Commands::SESSION_SETUP
    end

  end

end
