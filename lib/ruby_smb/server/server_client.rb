module RubySMB
  class Server
    class ServerClient

      require 'ruby_smb/dialect'
      require 'ruby_smb/signing'
      require 'ruby_smb/server/server_client/negotiation'
      require 'ruby_smb/server/server_client/session_setup'

      include RubySMB::Signing
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
        @session_key = nil
        @gss_authenticator = server.gss_provider.new_authenticator(self)
        @identity = nil
        @tree_connections = {}
        @preauth_integrity_hash_algorithm = nil
        @preauth_integrity_hash_value = nil
      end

      def metadialect
        Dialect::ALL[@dialect]
      end

      def getpeername
        @dispatcher.tcp_socket.getpeername
      end

      def handle_authenticated(raw_request)
        response = nil

        case raw_request[0...4]
        when "\xff\x53\x4d\x42".b
          raise NotImplementedError
        when "\xfe\x53\x4d\x42".b
          raise NotImplementedError
        end

        if response.nil?
          disconnect!
          return
        end

        send_packet(response)
      end

      def process_gss(buffer=nil)
        @gss_authenticator.process(buffer)
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
        if @state == :authenticated && @identity != Gss::Provider::IDENTITY_ANONYMOUS && !@session_key.nil?
          case metadialect.family
          when Dialect::FAMILY_SMB2
            packet = smb2_sign(packet)
          when Dialect::FAMILY_SMB3
            packet = smb3_sign(packet)
          end
        end

        @dispatcher.send_packet(packet)
      end

      def update_preauth_hash(data)
        unless @preauth_integrity_hash_algorithm
          raise RubySMB::Error::EncryptionError.new(
            'Cannot compute the Preauth Integrity Hash value: Preauth Integrity Hash Algorithm is nil'
          )
        end
        @preauth_integrity_hash_value = OpenSSL::Digest.digest(
          @preauth_integrity_hash_algorithm,
          @preauth_integrity_hash_value + data.to_binary_s
        )
      end
    end
  end
end
