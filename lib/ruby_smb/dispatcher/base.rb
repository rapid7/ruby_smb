# Provides the base class for the packet dispatcher.
class RubySMB::Dispatcher::Base
  # @param packet [#length]
  # @return [Fixnum] NBSS header to go in front of `packet`
  def nbss(packet)
    [packet.length].pack("N")
  end

  # @abstract
  def send_packet(packet)
    raise NotImplementedError
  end

  # @abstract
  def recv_packet
    raise NotImplementedError
  end
end
