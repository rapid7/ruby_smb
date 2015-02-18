require 'smb2/dispatcher'
class MockSocketDispatcher < Smb2::Dispatcher

  def recv_packet
    ""
  end

  def send_packet(packet)
  end

end
