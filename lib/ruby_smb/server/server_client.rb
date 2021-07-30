module RubySMB
  class Server
    class ServerClient

      require 'ruby_smb/server/server_client/negotiation'
      require 'ruby_smb/server/server_client/session_setup'
      require 'ruby_smb/server/server_client/tree_connect'

      include RubySMB::Server::ServerClient::Negotiation
      include RubySMB::Server::ServerClient::SessionSetup
      include RubySMB::Server::ServerClient::TreeConnect

      attr_reader :dialect, :state

      def initialize(server, dispatcher)
        @server = server
        @dispatcher = dispatcher
        @state = :negotiate
        @dialect = nil
        @message_id = 0
        @session_id = nil
        @gss_processor = server.gss_provider.new_processor(self)
        @identity = nil
        @tree_connections = {}
      end

      def handle_authenticated(raw_request)
        response = nil

        case raw_request[0...4]
        when "\xff\x53\x4d\x42".b
          raise NotImplementedError
        when "\xfe\x53\x4d\x42".b
          header = SMB2::SMB2Header.read(raw_request)
          case header.command
          when SMB2::Commands::TREE_CONNECT
            response = do_tree_connect_smb2(SMB2::Packet::TreeConnectRequest.read(raw_request))
          end

          unless response.nil?
            response.smb2_header.message_id = @message_id += 1
            response.smb2_header.session_id = @session_id
          end
        end

        if response.nil?
          disconnect!
          return
        end

        send_packet(response)
      end

      def process_gss(buffer)
        @gss_processor.process(buffer)
      end

      def run
        loop do
          begin
            raw_request = recv_packet
          rescue RubySMB::Error::CommunicationError
            break
          end

          case @state
          when :negotiate
            handle_negotiate(raw_request)
          when :session_setup
            handle_session_setup(raw_request)
          when :authenticated
            handle_authenticated(raw_request)
          end

          break if @dispatcher.tcp_socket.closed?
        end
      end

      def disconnect!
        @state = nil
        @dispatcher.tcp_socket.close
      end

      def recv_packet
        @dispatcher.recv_packet
      end

      def send_packet(packet)
        @dispatcher.send_packet(packet)
      end
    end
  end
end
