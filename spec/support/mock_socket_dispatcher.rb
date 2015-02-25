require 'smb2/dispatcher'
class MockSocketDispatcher < Smb2::Dispatcher::Base

  def recv_packet
    ""
  end

  def send_packet(packet)
  end

end
