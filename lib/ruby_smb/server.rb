require 'logger'
require 'socket'

module RubySMB
  # This class provides the SMB server core. Settings that are relevant server wide are managed by this object.
  # Currently, the server only supports negotiating and authenticating requests. No other server functionality is
  # available at this time. The negotiating and authentication is supported for SMB versions 1 through 3.1.1.
  class Server
    require 'ruby_smb/server/server_client'
    require 'ruby_smb/server/session'
    require 'ruby_smb/server/share'
    require 'ruby_smb/gss/provider/ntlm'

    Connection = Struct.new(:client, :thread)

    # @param server_sock the socket on which the server should listen
    # @param [Gss::Provider] the authentication provider
    def initialize(server_sock: nil, gss_provider: nil, logger: nil)
      server_sock = ::TCPServer.new(445) if server_sock.nil?

      @guid = Random.new.bytes(16)
      @socket = server_sock
      @connections = []
      @gss_provider = gss_provider || Gss::Provider::NTLM.new
      # reject the wildcard dialect because it's not a real dialect we can use for this purpose
      @dialects = RubySMB::Dialect::ALL.keys.reject { |dialect| dialect == "0x%04x" % RubySMB::SMB2::SMB2_WILDCARD_REVISION }.reverse

      case logger
      when nil
        @logger = Logger.new(File.open(File::NULL, 'w'))
      when :stdout
        @logger = Logger.new(STDOUT)
      when :stderr
        @logger = Logger.new(STDERR)
      else
        @logger = logger
      end

      # share name => provider instance
      @shares = {
        'IPC$' => Share::Provider::IpcPipe.new
      }
    end

    def add_share(share_provider)
      logger.debug("Adding #{share_provider.type} share: #{share_provider.name}")
      @shares[share_provider.name] = share_provider
    end

    # Run the server and accept any connections. For each connection, the block will be executed if specified. When the
    # block returns false, the loop will exit and the server will no long accept new connections.
    def run(&block)
      loop do
        sock = @socket.accept
        server_client = ServerClient.new(self, RubySMB::Dispatcher::Socket.new(sock, read_timeout: nil))
        @connections << Connection.new(server_client, Thread.new { server_client.run })

        break unless block.nil? || block.call(server_client)
      end
    end

    # The dialects that this server will negotiate with clients, in ascending order of preference.
    # @!attribute [rw] dialects
    #   @return [Array<String>]
    attr_accessor :dialects

    # The GSS Provider instance that this server will use to authenticate
    # incoming client connections.
    # @!attribute [r] gss_provider
    #   @return [RubySMB::Gss::Provider::Base]
    attr_reader :gss_provider

    # The 16 byte GUID that uniquely identifies this server instance.
    # @!attribute [r] guid
    attr_reader :guid

    # The logger instance to use for diagnostic messages.
    # @!attribute [r] logger
    attr_reader :logger

    # The shares that are provided by this server
    # @!attribute [r] shares
    attr_reader :shares
  end
end

