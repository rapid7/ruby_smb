require 'socket'

module RubySMB
  # This class provides the SMB server core. Settings that are relevant server wide are managed by this object.
  # Currently, the server only supports negotiating and authenticating requests. No other server functionality is
  # available at this time. The negotiating and authentication is supported for SMB versions 1 through 3.1.1.
  class Server
    require 'ruby_smb/server/server_client'
    require 'ruby_smb/gss/provider/ntlm'

    Connection = Struct.new(:client, :thread)

    # @param server_sock the socket on which the server should listen
    # @param [Gss::Provider] the authentication provider
    def initialize(server_sock: nil, gss_provider: nil)
      server_sock = ::TCPServer.new(445) if server_sock.nil?

      @server_guid = Random.bytes(16)
      @server_sock = server_sock
      @connections = []
      @gss_provider = gss_provider || Gss::Provider::NTLM.new
    end

    # Run the server and accept any connections. For each connection, the block will be executed if specified. When the
    # block returns false, the loop will exit and the server will no long accept new connections.
    def run(&block)
      loop do
        sock = @server_sock.accept
        server_client = ServerClient.new(self, RubySMB::Dispatcher::Socket.new(sock))
        @connections << Connection.new(server_client, Thread.new { server_client.run })

        break unless block.nil? || block.call(server_client)
      end
    end

    attr_reader :gss_provider, :server_guid
  end
end

