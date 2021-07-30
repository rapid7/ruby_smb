require 'socket'

module RubySMB
  class Server
    require 'ruby_smb/server/server_client'
    require 'ruby_smb/gss/provider/ntlm'

    Connection = Struct.new(:client, :thread)

    def initialize(server_sock: nil, gss_provider: nil)
      server_sock = ::TCPServer.new(445) if server_sock.nil?

      @server_guid = SecureRandom.random_bytes(16)
      @server_sock = server_sock
      @connections = []
      @gss_provider = gss_provider || Gss::Provider::NTLM.new
    end

    def run(&block)
      loop do
        sock = @server_sock.accept
        server_client = ServerClient.new(self, RubySMB::Dispatcher::Socket.new(sock))
        @connections << Connection.new(server_client, Thread.new { server_client.run })

        break unless block.nil? || block.call(server_client)
      end
    end

    attr_accessor :gss_provider, :server_guid
  end
end

