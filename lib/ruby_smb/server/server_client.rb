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
        @message_id = 0
        @session_id = nil
        @gss_processor = server.gss_provider.new_processor(self)
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
