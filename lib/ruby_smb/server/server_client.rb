module RubySMB
  class Server
    # This class represents a single connected client to the server. It stores and processes connection specific related
    # information.
    class ServerClient

      require 'ruby_smb/dialect'
      require 'ruby_smb/signing'
      require 'ruby_smb/server/server_client/encryption'
      require 'ruby_smb/server/server_client/negotiation'
      require 'ruby_smb/server/server_client/session_setup'
      require 'ruby_smb/server/server_client/share_io'
      require 'ruby_smb/server/server_client/tree_connect'

      include RubySMB::Signing
      include RubySMB::Server::ServerClient::Encryption
      include RubySMB::Server::ServerClient::Negotiation
      include RubySMB::Server::ServerClient::SessionSetup
      include RubySMB::Server::ServerClient::ShareIO
      include RubySMB::Server::ServerClient::TreeConnect

      attr_reader :dialect, :dispatcher, :session_table

      # @param [Server] server the server that accepted this connection
      # @param [Dispatcher::Socket] dispatcher the connection's socket dispatcher
      def initialize(server, dispatcher)
        @server = server
        @dispatcher = dispatcher
        @dialect = nil
        @sequence_counter = 0
        @cipher_id = 0
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

      def peerhost
        ::Socket::unpack_sockaddr_in(getpeername)[1]
      end

      def peerport
        ::Socket::unpack_sockaddr_in(getpeername)[0]
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
          rescue NotImplementedError => e
            message = "Caught a NotImplementedError while handling a #{SMB1::Commands.name(header.command)} request"
            message << " (#{e.message})" if e.message
            logger.error(message)
            response = RubySMB::SMB1::Packet::EmptyPacket.new
            response.smb_header.nt_status = WindowsError::NTStatus::STATUS_NOT_SUPPORTED
          end

          unless response.nil?
            # set these header fields if they were not initialized
            if response.is_a?(SMB1::Packet::EmptyPacket)
              response.smb_header.command = header.command if response.smb_header.command == 0
              response.smb_header.flags.reply = 1
              nt_status = response.smb_header.nt_status.to_i
              message = "Sending an error packet for SMB1 command: #{SMB1::Commands.name(header.command)}, status: 0x#{nt_status.to_s(16).rjust(8, '0')}"
              if (nt_status_name = WindowsError::NTStatus.find_by_retval(nt_status).first&.name)
                message << " (#{nt_status_name})"
              end
              logger.info(message)
            end

            response.smb_header.pid_high = header.pid_high if response.smb_header.pid_high == 0
            response.smb_header.tid = header.tid if response.smb_header.tid == 0
            response.smb_header.pid_low = header.pid_low if response.smb_header.pid_low == 0
            response.smb_header.uid = header.uid if response.smb_header.uid == 0
            response.smb_header.mid = header.mid if response.smb_header.mid == 0
          end
        when RubySMB::SMB2::SMB2_PROTOCOL_ID
          response = _handle_smb2(raw_request)
        when RubySMB::SMB2::SMB2_TRANSFORM_PROTOCOL_ID
          begin
            header = RubySMB::SMB2::Packet::TransformHeader.read(raw_request)
          rescue IOError => e
            logger.error("Caught a #{e.class} while reading the SMB3 Transform header")
            disconnect!
            return
          end

          begin
            response = handle_smb3_transform(raw_request, header)
          rescue NotImplementedError
            logger.error("Caught a NotImplementedError while handling a SMB3 Transform request")
            response = SMB2::Packet::ErrorPacket.new
            response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NOT_SUPPORTED
            response.smb2_header.session_id = header.session_id
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

        disconnect!
      end

      #
      # Disconnect the remote client.
      #
      def disconnect!
        @dialect = nil
        @dispatcher.tcp_socket.close unless @dispatcher.tcp_socket.closed?
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
          @in_packet_queue += split_smb2_chain(packet)
          packet = @in_packet_queue.shift
        end

        packet
      end

      #
      # Send a single SMB packet using the dispatcher. If necessary, the packet will be signed.
      #
      # @param [GenericPacket] packet the packet to send
      def send_packet(packet)
        case metadialect&.family
        when Dialect::FAMILY_SMB1
          session_id = packet.smb_header.uid
        when Dialect::FAMILY_SMB2
          session_id = packet.smb2_header.session_id
        when Dialect::FAMILY_SMB3
          if packet.is_a?(RubySMB::SMB2::Packet::TransformHeader)
            session_id = packet.session_id
          else
            session_id = packet.smb2_header.session_id
          end
        end
        session = @session_table[session_id]

        unless session.nil? || session.is_anonymous || session.key.nil? || packet.is_a?(RubySMB::SMB2::Packet::TransformHeader)
          case metadialect&.family
          when Dialect::FAMILY_SMB1
            packet = Signing::smb1_sign(packet, session.key, @sequence_counter)
          when Dialect::FAMILY_SMB2
            packet = Signing::smb2_sign(packet, session.key)
          when Dialect::FAMILY_SMB3
            packet = Signing::smb3_sign(packet, session.key, @dialect, @preauth_integrity_hash_value)
          end
        end

        @sequence_counter += 1
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
        session = @session_table[header.uid]

        if session.nil? && !(header.command == SMB1::Commands::SMB_COM_SESSION_SETUP_ANDX && header.uid == 0)
          response = SMB1::Packet::EmptyPacket.new
          response.smb_header.nt_status = WindowsError::NTStatus::STATUS_USER_SESSION_DELETED
          return response
        end
        if session&.state == :expired
          response = SMB1::Packet::EmptyPacket.new
          response.smb_header.nt_status = WindowsError::NTStatus::STATUS_NETWORK_SESSION_EXPIRED
          return response
        end

        case header.command
        when SMB1::Commands::SMB_COM_CLOSE
          dispatcher, request_class = :do_close_smb1, SMB1::Packet::CloseRequest
        when SMB1::Commands::SMB_COM_TREE_DISCONNECT
          dispatcher, request_class = :do_tree_disconnect_smb1, SMB1::Packet::TreeDisconnectRequest
        when SMB1::Commands::SMB_COM_LOGOFF_ANDX
          dispatcher, request_class = :do_logoff_andx_smb1, SMB1::Packet::LogoffRequest
        when SMB1::Commands::SMB_COM_NT_CREATE_ANDX
          dispatcher, request_class = :do_nt_create_andx_smb1, SMB1::Packet::NtCreateAndxRequest
        when SMB1::Commands::SMB_COM_READ_ANDX
          dispatcher, request_class = :do_read_andx_smb1, SMB1::Packet::ReadAndxRequest
        when SMB1::Commands::SMB_COM_SESSION_SETUP_ANDX
          dispatcher, request_class = :do_session_setup_andx_smb1, SMB1::Packet::SessionSetupRequest
        when SMB1::Commands::SMB_COM_TRANSACTION2
          dispatcher, request_class = :do_transactions2_smb1, SMB1::Packet::Trans2::Request
        when SMB1::Commands::SMB_COM_TREE_CONNECT
          dispatcher, request_class = :do_tree_connect_smb1, SMB1::Packet::TreeConnectRequest
        else
          logger.warn("The SMB1 #{SMB1::Commands.name(header.command)} command is not supported")
          raise NotImplementedError
        end

        begin
          request = request_class.read(raw_request)
        rescue IOError, RubySMB::Error::InvalidPacket => e
          logger.error("Caught a #{e.class} while reading the SMB1 #{request_class} (#{e.message})")
          response = RubySMB::SMB1::Packet::EmptyPacket.new
          response.smb_header.nt_status = WindowsError::NTStatus::STATUS_DATA_ERROR
          return response
        end

        if request.is_a?(SMB1::Packet::EmptyPacket)
          logger.error("Received an error packet for SMB1 command: #{SMB1::Commands.name(header.command)}")
          response = RubySMB::SMB1::Packet::EmptyPacket.new
          response.smb_header.nt_status = WindowsError::NTStatus::STATUS_DATA_ERROR
          return response
        end

        logger.debug("Dispatching request to #{dispatcher} (session: #{session.inspect})")
        send(dispatcher, request, session)
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
        if session&.state == :expired
          response = SMB2::Packet::ErrorPacket.new
          response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NETWORK_SESSION_EXPIRED
          return response
        end

        case header.command
        when SMB2::Commands::CLOSE
          dispatcher, request_class = :do_close_smb2, SMB2::Packet::CloseRequest
        when SMB2::Commands::CREATE
          dispatcher, request_class = :do_create_smb2, SMB2::Packet::CreateRequest
        when SMB2::Commands::IOCTL
          dispatcher, request_class = :do_ioctl_smb2, SMB2::Packet::IoctlRequest
        when SMB2::Commands::LOGOFF
          dispatcher, request_class = :do_logoff_smb2, SMB2::Packet::LogoffRequest
        when SMB2::Commands::QUERY_DIRECTORY
          dispatcher, request_class = :do_query_directory_smb2, SMB2::Packet::QueryDirectoryRequest
        when SMB2::Commands::QUERY_INFO
          dispatcher, request_class = :do_query_info_smb2, SMB2::Packet::QueryInfoRequest
        when SMB2::Commands::READ
          dispatcher, request_class = :do_read_smb2, SMB2::Packet::ReadRequest
        when SMB2::Commands::SESSION_SETUP
          dispatcher, request_class = :do_session_setup_smb2, SMB2::Packet::SessionSetupRequest
        when SMB2::Commands::TREE_CONNECT
          dispatcher, request_class = :do_tree_connect_smb2, SMB2::Packet::TreeConnectRequest
        when SMB2::Commands::TREE_DISCONNECT
          dispatcher, request_class = :do_tree_disconnect_smb2, SMB2::Packet::TreeDisconnectRequest
        else
          logger.warn("The SMB2 #{SMB2::Commands.name(header.command)} command is not supported")
          raise NotImplementedError
        end

        begin
          request = request_class.read(raw_request)
        rescue IOError, RubySMB::Error::InvalidPacket => e
          logger.error("Caught a #{e.class} while reading the SMB2 #{request_class} (#{e.message})")
          response = RubySMB::SMB2::Packet::ErrorPacket.new
        end

        if request.is_a?(SMB2::Packet::ErrorPacket)
          logger.error("Received an error packet for SMB2 command: #{SMB2::Commands.name(header.command)}")
          response.smb_header.nt_status = WindowsError::NTStatus::STATUS_DATA_ERROR
          return response
        end

        logger.debug("Dispatching request to #{dispatcher} (session: #{session.inspect})")
        send(dispatcher, request, session)
      end

      def _handle_smb2(raw_request)
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
            nt_status = response.smb2_header.nt_status.to_i
            message = "Sending an error packet for SMB2 command: #{SMB2::Commands.name(header.command)}, status: 0x#{nt_status.to_s(16).rjust(8, '0')}"
            if (nt_status_name = WindowsError::NTStatus.find_by_retval(nt_status).first&.name)
              message << " (#{nt_status_name})"
            end
            logger.info(message)
          end

          response.smb2_header.credits = 1 if response.smb2_header.credits == 0
          response.smb2_header.message_id = header.message_id if response.smb2_header.message_id == 0
          response.smb2_header.session_id = header.session_id if response.smb2_header.session_id == 0
          response.smb2_header.tree_id = header.tree_id if response.smb2_header.tree_id == 0
        end

        response
      end

      def handle_smb3_transform(raw_request, header)
        session = @session_table[header.session_id]
        if session.nil?
          response = SMB2::Packet::ErrorPacket.new
          response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_USER_SESSION_DELETED
          return response
        end

        chain = split_smb2_chain(smb3_decrypt(header, session))
        chain[0...-1].each do |pt_raw_request|
          pt_response = _handle_smb2(pt_raw_request)
          return if pt_response.nil?

          send_packet(smb3_encrypt(pt_response, session))
        end

        pt_response = _handle_smb2(chain.last)
        return if pt_response.nil?

        smb3_encrypt(pt_response, session)
      end

      def split_smb2_chain(buffer)
        chain = []
        header = RubySMB::SMB2::SMB2Header.read(buffer)
        unless header.next_command == 0
          until header.next_command == 0
            chain << buffer[0...header.next_command]
            buffer = buffer[header.next_command..-1]
            header = RubySMB::SMB2::SMB2Header.read(buffer)
          end
        end

        chain << buffer
        chain
      end
    end
  end
end
