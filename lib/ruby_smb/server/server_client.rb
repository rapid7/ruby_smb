module RubySMB
  class Server
    class ServerClient

      require 'ruby_smb/server/server_client/negotiation'
      require 'ruby_smb/server/server_client/session_setup'

      include RubySMB::Server::ServerClient::Negotiation
      include RubySMB::Server::ServerClient::SessionSetup

      attr_reader :dialect, :state

      def initialize(server, dispatcher)
        @server = server
        @dispatcher = dispatcher
        @state = :negotiate
        @dialect = nil
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
          when :session_setup1
            handle_session_setup1(raw_request)
          when :session_setup2
            handle_session_setup2(raw_request)
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
