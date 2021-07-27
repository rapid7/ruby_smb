require 'socket'

module RubySMB
  class Server
    require 'ruby_smb/server/server_client'

    Connection = Struct.new(:client, :thread)

    def initialize(server_sock: nil)
      server_sock = ::TCPServer.new(445) if server_sock.nil?

      @server_guid = SecureRandom.random_bytes(16)
      @server_sock = server_sock
      @connections = []
    end

    def run(&block)
      loop do
        sock = @server_sock.accept
        server_client = ServerClient.new(self, RubySMB::Dispatcher::Socket.new(sock))
        @connections << Connection.new(server_client, Thread.new { server_client.run })

        break unless block.nil? || block.call
      end
    end

    attr_accessor :server_guid
  end
end

