module RubySMB
  class Server
    # This class represents a single connected client to the server. It stores and processes connection specific related
    # information.
    class ServerClient

      require 'ruby_smb/dialect'
      require 'ruby_smb/signing'
      require 'ruby_smb/server/server_client/negotiation'
      require 'ruby_smb/server/server_client/session_setup'
      require 'ruby_smb/server/server_client/share_io'
      require 'ruby_smb/server/server_client/tree_connect'

      include RubySMB::Signing
      include RubySMB::Server::ServerClient::Negotiation
      include RubySMB::Server::ServerClient::SessionSetup
      include RubySMB::Server::ServerClient::ShareIO
      include RubySMB::Server::ServerClient::TreeConnect

      attr_reader :dialect, :session_table

      # @param [Server] server the server that accepted this connection
      # @param [Dispatcher::Socket] dispatcher the connection's socket dispatcher
      def initialize(server, dispatcher)
        @server = server
        @dispatcher = dispatcher
        @dialect = nil
        @gss_authenticator = server.gss_provider.new_authenticator(self)
        @preauth_integrity_hash_algorithm = nil
        @preauth_integrity_hash_value = nil
        @in_packet_queue = []

        # session id => session instance
        @session_table = {}
      end

      #
      # The dialects metadata definition.
      #
      # @return [Dialect::Definition]
      def metadialect
        Dialect::ALL[@dialect]
      end

      #
      # The peername of the connected socket. This is a combination of the IPv4 or IPv6 address and port number.
      #
      # @example Parse the value into an IP address
      #   ::Socket::unpack_sockaddr_in(server_client.getpeername)
      #
      # @return [String]
      def getpeername
        @dispatcher.tcp_socket.getpeername
      end

      #
      # Handle a request after the dialect has been negotiated. This is the main
      # handler for all requests after the connection has been established. If a
      # request handler raises NotImplementedError, the server will respond to
      # the client with NT Status STATUS_NOT_SUPPORTED.
      #
      # @param [String] raw_request the request that should be handled
      def handle_smb(raw_request)
        response = nil

        case raw_request[0...4].unpack1('L>')
        when RubySMB::SMB1::SMB_PROTOCOL_ID
          begin
            header = RubySMB::SMB1::SMBHeader.read(raw_request)
          rescue IOError => e
            logger.error("Caught a #{e.class} while reading the SMB1 header (#{e.message})")
            disconnect!
            return
          end

          begin
            response = handle_smb1(raw_request, header)
          rescue NotImplementedError
            logger.error("Caught a NotImplementedError while handling a #{SMB1::Commands.name(header.command)} request")
            response = RubySMB::SMB1::Packet::EmptyPacket.new
            response.smb_header.nt_status = WindowsError::NTStatus::STATUS_NOT_SUPPORTED
          end

          unless response.nil?
            # set these header fields if they were not initialized
            if response.is_a?(SMB1::Packet::EmptyPacket)
              response.smb_header.command = header.command
              response.smb_header.flags.reply = 1
            end

            response.smb_header.pid_high = header.pid_high if response.smb_header.pid_high == 0
            response.smb_header.tid = header.tid if response.smb_header.tid == 0
            response.smb_header.pid_low = header.pid_low if response.smb_header.pid_low == 0
            response.smb_header.uid = header.uid if response.smb_header.uid == 0
            response.smb_header.mid = header.mid if response.smb_header.mid == 0
          end
        when RubySMB::SMB2::SMB2_PROTOCOL_ID
          begin
            header = RubySMB::SMB2::SMB2Header.read(raw_request)
          rescue IOError => e
            logger.error("Caught a #{e.class} while reading the SMB2 header (#{e.message})")
            disconnect!
            return
          end

          begin
            response = handle_smb2(raw_request, header)
          rescue NotImplementedError
            logger.error("Caught a NotImplementedError while handling a #{SMB2::Commands.name(header.command)} request")
            response = SMB2::Packet::ErrorPacket.new
            response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NOT_SUPPORTED
          end

          unless response.nil?
            # set these header fields if they were not initialized
            if response.is_a?(SMB2::Packet::ErrorPacket)
              response.smb2_header.command = header.command if response.smb2_header.command == 0
              response.smb2_header.flags.reply = 1
            end

            response.smb2_header.credits = 1 if response.smb2_header.credits == 0
            response.smb2_header.message_id = header.message_id if response.smb2_header.message_id == 0
            response.smb2_header.session_id = header.session_id if response.smb2_header.session_id == 0
            response.smb2_header.tree_id = header.tree_id if response.smb2_header.tree_id == 0
          end
        end

        if response.nil?
          disconnect!
          return
        end

        send_packet(response)
      end

      #
      # Process a GSS authentication buffer. If no buffer is specified, the request is assumed to be the first in the
      # negotiation sequence.
      #
      # @param [String, nil] buffer the request GSS request buffer that should be processed
      # @return [Gss::Provider::Result] the result of the processed GSS request
      def process_gss(buffer=nil)
        @gss_authenticator.process(buffer)
      end

      #
      # Run the processing loop to receive and handle requests. This loop runs until an exception occurs or the
      # dispatcher socket is closed.
      #
      def run
        loop do
          begin
            raw_request = recv_packet
          rescue RubySMB::Error::CommunicationError
            break
          end

          if @dialect.nil?
            handle_negotiate(raw_request)
            logger.info("Negotiated dialect: #{RubySMB::Dialect[@dialect].full_name}") unless @dialect.nil?
          else
            handle_smb(raw_request)
          end

          break if @dispatcher.tcp_socket.closed?
        end
      end

      #
      # Disconnect the remote client.
      #
      def disconnect!
        @dialect = nil
        @dispatcher.tcp_socket.close
      end

      #
      # The logger object associated with this instance.
      #
      # @return [Logger]
      def logger
        @server.logger
      end

      #
      # Receive a single SMB packet from the dispatcher.
      #
      # @return [String] the raw packet
      def recv_packet
        return @in_packet_queue.shift if @in_packet_queue.length > 0

        packet = @dispatcher.recv_packet
        if packet && packet.length >= 4 && packet[0...4].unpack1('L>') == RubySMB::SMB2::SMB2_PROTOCOL_ID
          header = RubySMB::SMB2::SMB2Header.read(packet)
          unless header.next_command == 0
            until header.next_command == 0
              @in_packet_queue.push(packet[0...header.next_command])
              packet = packet[header.next_command..-1]
              header = RubySMB::SMB2::SMB2Header.read(packet)
            end

            @in_packet_queue.push(packet)
            packet = @in_packet_queue.shift
          end
        end

        packet
      end

      #
      # Send a single SMB packet using the dispatcher. If necessary, the packet will be signed.
      #
      # @param [GenericPacket] packet the packet to send
      def send_packet(packet)
        case metadialect&.order
        when Dialect::ORDER_SMB1
          session_id = packet.smb_header.uid
        when Dialect::ORDER_SMB2
          session_id = packet.smb2_header.session_id
        end
        session = @session_table[session_id]

        unless session.nil? || session.is_anonymous || session.key.nil?
          case metadialect&.family
          when Dialect::FAMILY_SMB2
            packet = Signing::smb2_sign(packet, session.key)
          when Dialect::FAMILY_SMB3
            packet = Signing::smb3_sign(packet, session.key, @dialect, @preauth_integrity_hash_value)
          end
        end

        @dispatcher.send_packet(packet)
      end

      #
      # Update the preauth integrity hash as used by dialect 3.1.1 for various cryptographic operations. The algorithm
      # and hash values must have been initialized prior to calling this.
      #
      # @param [String] data the data with which to update the preauth integrity hash
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

      private

      #
      # Handle an SMB version 1 message.
      #
      # @param [String] raw_request The bytes of the entire SMB request.
      # @param [RubySMB::SMB1::SMBHeader] header The request header.
      # @return [RubySMB::GenericPacket]
      def handle_smb1(raw_request, header)
        # session = @session_table[header.uid]

        case header.command
        when SMB1::Commands::SMB_COM_SESSION_SETUP_ANDX
          response = do_session_setup_smb1(SMB1::Packet::SessionSetupRequest.read(raw_request))
        else
          logger.warn("The SMB1 #{SMB1::Commands.name(header.command)} command is not supported")
          raise NotImplementedError
        end

        response
      end

      #
      # Handle an SMB version 2 or 3 message.
      #
      # @param [String] raw_request The bytes of the entire SMB request.
      # @param [RubySMB::SMB2::SMB2Header] header The request header.
      # @return [RubySMB::GenericPacket]
      # @raise [NotImplementedError] Raised when the requested operation is not
      #   supported.
      def handle_smb2(raw_request, header)
        session = @session_table[header.session_id]

        if session.nil? && !(header.command == SMB2::Commands::SESSION_SETUP && header.session_id == 0)
          response = SMB2::Packet::ErrorPacket.new
          response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_USER_SESSION_DELETED
          return response
        end

        case header.command
        when SMB2::Commands::CLOSE
          response = do_close_smb2(SMB2::Packet::CloseRequest.read(raw_request), session)
        when SMB2::Commands::CREATE
          response = do_create_smb2(SMB2::Packet::CreateRequest.read(raw_request), session)
        when SMB2::Commands::IOCTL
          response = do_ioctl_smb2(SMB2::Packet::IoctlRequest.read(raw_request), session)
        when SMB2::Commands::LOGOFF
          response = do_logoff_smb2(SMB2::Packet::LogoffRequest.read(raw_request), session)
        when SMB2::Commands::QUERY_DIRECTORY
          response = do_query_directory_smb2(SMB2::Packet::QueryDirectoryRequest.read(raw_request), session)
        when SMB2::Commands::QUERY_INFO
          response = do_query_info_smb2(SMB2::Packet::QueryInfoRequest.read(raw_request), session)
        when SMB2::Commands::READ
          response = do_read_smb2(SMB2::Packet::ReadRequest.read(raw_request), session)
        when SMB2::Commands::SESSION_SETUP
          response = do_session_setup_smb2(SMB2::Packet::SessionSetupRequest.read(raw_request))
        when SMB2::Commands::TREE_CONNECT
          response = do_tree_connect_smb2(SMB2::Packet::TreeConnectRequest.read(raw_request), session)
        when SMB2::Commands::TREE_DISCONNECT
          response = do_tree_disconnect_smb2(SMB2::Packet::TreeDisconnectRequest.read(raw_request), session)
        else
          logger.warn("The SMB2 #{SMB2::Commands.name(header.command)} command is not supported")
          raise NotImplementedError
        end

        response
      end
    end
  end
end
