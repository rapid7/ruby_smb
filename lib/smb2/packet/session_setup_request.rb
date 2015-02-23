require 'smb2/packet'

class Smb2::Packet

  class SessionSetupRequest < Smb2::Packet
    nest :header, RequestHeader
    unsigned :struct_size,   16, default: 25
    unsigned :flags,          8, default: 0x00
    # @see Packet::SECURITY_MODES
    unsigned :security_mode,  8

    unsigned :capabilities,  32, default: 0x0000_0001
    unsigned :channel,       32, default: 0

    data_buffer :security_blob

    unsigned :previous_session_id, 64

    # @todo Consider giving this an NTLM class so bit-struct will instantiate
    # for us automatically
    rest :buffer

    FLAGS = {
      SESSION_BINDING_REQUEST: 0x0000_0001
    }.freeze
    FLAG_NAMES = FLAGS.keys

    def initialize(*args)
      super
      new_header = self.header
      new_header.command = Smb2::Commands::SESSION_SETUP
      self.header = new_header
    end

  end

end
