require 'smb2/packet'
require 'net/ntlm/client'

class Smb2::Client

  attr_reader :socket

  def initialize(socket)
    @socket = socket
  end

  def session_setup(username, password)
    Smb2::Packet::SessionSetupRequest.new(
      security_mode: SecurityModes::SIGNING_ENABLED
    )
    @ntlm_client = Net::NTLM::Client.new(username, password)

    @ntlm_client.init_context
  end

end
