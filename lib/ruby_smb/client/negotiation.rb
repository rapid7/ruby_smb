require 'securerandom'
module RubySMB
  class Client
    # This module holds all of the methods backing the {RubySMB::Client#negotiate} method
    module Negotiation
      # Handles the entire SMB Multi-Protocol Negotiation from the
      # Client to the Server. It sets state on the client appropriate
      # to the protocol and capabilites negotiated during the exchange.
      # It also keeps track of the negotiated dialect.
      #
      # @return [void]
      def negotiate
        request_packet  = negotiate_request
        raw_response    = send_recv(request_packet)
        response_packet = negotiate_response(raw_response)
        # The list of dialect identifiers sent to the server is stored
        # internally to be able to retrieve the negotiated dialect later on.
        # This is only valid for SMB1.
        response_packet.dialects = request_packet.dialects if response_packet.respond_to? :dialects=
        version = parse_negotiate_response(response_packet)
        if @encryption_required
          case @dialect
          when '0x0300', '0x0302'
            @encryption_algorithm = RubySMB::SMB2::EncryptionCapabilities::ENCRYPTION_ALGORITM_MAP[RubySMB::SMB2::EncryptionCapabilities::AES_128_CCM]
          when '0x0311'
            parse_smb3_encryption_data(request_packet, response_packet)
          end
        end
        # If the response contains the SMB2 wildcard revision number dialect;
        # it indicates that the server implements SMB 2.1 or future dialect
        # revisions and expects the client to send a subsequent SMB2 Negotiate
        # request to negotiate the actual SMB 2 Protocol revision to be used.
        # The wildcard revision number is sent only in response to a
        # multi-protocol negotiate request with the "SMB 2.???" dialect string.
        if self.dialect == '0x02ff'
          self.smb2_message_id += 1
          negotiate
        end
        version
      rescue RubySMB::Error::InvalidPacket, Errno::ECONNRESET
        error = 'Unable to Negotiate with remote host'
        error << ', SMB1 may be disabled' if smb1 && !smb2
        raise RubySMB::Error::NegotiationFailure, error
      end

      # Creates the first Negotiate Request Packet according to the SMB version
      # used.
      #
      # @return [RubySMB::SMB1::Packet::NegotiateRequest] a SMB1 Negotiate Request packet if SMB1 is used
      # @return [RubySMB::SMB1::Packet::NegotiateRequest] a SMB2 Negotiate Request packet if SMB2 is used
      def negotiate_request
        if smb1
          smb1_negotiate_request
        elsif smb2
          smb2_negotiate_request
        elsif smb3
          smb3_negotiate_request
        end
      end

      # Takes the raw response data from the server and tries
      # parse it into a valid Response packet object.
      # This method currently assumes that all SMB1 will use Extended Security.
      #
      # @param raw_data [String] the raw binary response from the server
      # @return [RubySMB::SMB1::Packet::NegotiateResponseExtended] when the response is an SMB1 Extended Security Negotiate Response Packet
      # @return [RubySMB::SMB2::Packet::NegotiateResponse] when the response is an SMB2 Negotiate Response Packet
      def negotiate_response(raw_data)
        response = nil
        if smb1
          packet = RubySMB::SMB1::Packet::NegotiateResponseExtended.read raw_data
          response = packet if packet.valid?
        end
        if (smb2 || smb3) && response.nil?
          packet = RubySMB::SMB2::Packet::NegotiateResponse.read raw_data
          response = packet if packet.valid?
        end
        if response.nil?
          if packet.packet_smb_version == 'SMB1'
            extended_security = if packet.is_a? RubySMB::SMB1::Packet::NegotiateResponseExtended
              packet.parameter_block.capabilities.extended_security
            else
              "n/a"
            end
            raise RubySMB::Error::InvalidPacket.new(
              expected_proto:  RubySMB::SMB1::SMB_PROTOCOL_ID,
              expected_cmd:    RubySMB::SMB1::Packet::NegotiateResponseExtended::COMMAND,
              expected_custom: "extended_security=1",
              received_proto:  packet.smb_header.protocol,
              received_cmd:    packet.smb_header.command,
              received_custom: "extended_security=#{extended_security}"
            )
          elsif packet.packet_smb_version == 'SMB2'
            raise RubySMB::Error::InvalidPacket.new(
              expected_proto:  RubySMB::SMB2::SMB2_PROTOCOL_ID,
              expected_cmd:    RubySMB::SMB2::Packet::NegotiateResponse::COMMAND,
              received_proto:  packet.smb2_header.protocol,
              received_cmd:    packet.smb2_header.command
            )
          else
            raise RubySMB::Error::InvalidPacket, 'Unknown SMB protocol version'
          end
        end
        response
      end

      # Sets the supported SMB Protocol and whether or not
      # Signing is enabled based on the Negotiate Response Packet.
      # It also stores the negotiated dialect.
      #
      # @param packet [RubySMB::SMB1::Packet::NegotiateResponseExtended] if SMB1 was negotiated
      # @param packet [RubySMB::SMB2::Packet::NegotiateResponse] if SMB2 was negotiated
      # @return [String] The SMB version as a string ('SMB1', 'SMB2')
      def parse_negotiate_response(packet)
        case packet
        when RubySMB::SMB1::Packet::NegotiateResponseExtended
          self.smb1 = true
          self.smb2 = false
          self.smb3 = false
          self.signing_required = packet.parameter_block.security_mode.security_signatures_required == 1
          self.dialect = packet.negotiated_dialect.to_s
          # MaxBufferSize is largest message server will receive, measured from start of the SMB header. Subtract 260
          # for protocol overhead. Then this value can be used for max read/write size without having to factor in
          # protocol overhead every time.
          self.server_max_buffer_size = packet.parameter_block.max_buffer_size - 260
          'SMB1'
        when RubySMB::SMB2::Packet::NegotiateResponse
          self.smb1 = false
          unless packet.dialect_revision.to_i == 0x02ff
            self.smb2 = packet.dialect_revision.to_i >= 0x0200 && packet.dialect_revision.to_i < 0x0300
            self.smb3 = packet.dialect_revision.to_i >= 0x0300
          end
          self.signing_required = packet.security_mode.signing_required == 1 if self.smb2
          self.dialect = "0x%04x" % packet.dialect_revision
          self.server_max_read_size = packet.max_read_size
          self.server_max_write_size = packet.max_write_size
          self.server_max_transact_size = packet.max_transact_size
          # This value is used in SMB1 only but calculate a valid value anyway
          self.server_max_buffer_size = [self.server_max_read_size, self.server_max_write_size, self.server_max_transact_size].min
          return self.smb2 ? 'SMB2' : 'SMB3'
        end
      end

      def parse_smb3_encryption_data(request_packet, response_packet)
        nc = response_packet.find_negotiate_context(
          RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        )
        @preauth_integrity_hash_algorithm = RubySMB::SMB2::PreauthIntegrityCapabilities::HASH_ALGORITM_MAP[nc&.data&.hash_algorithms&.first]
        unless @preauth_integrity_hash_algorithm
          raise RubySMB::Error::EncryptionError.new(
            'Unable to retrieve the Preauth Integrity Hash Algorithm from the Negotiate response'
          )
        end
        # Set the encryption the client will use, prioritizing AES_128_GCM over AES_128_CCM
        nc = response_packet.find_negotiate_context(
          RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES
        )
        ciphers = nc&.data&.ciphers
        unless ciphers
          raise RubySMB::Error::EncryptionError.new(
            'Unable to retrieve the encryption cipher list supported by the server from the Negotiate response'
          )
        end
        if ciphers.include?(RubySMB::SMB2::EncryptionCapabilities::AES_128_GCM)
          @encryption_algorithm = RubySMB::SMB2::EncryptionCapabilities::ENCRYPTION_ALGORITM_MAP[RubySMB::SMB2::EncryptionCapabilities::AES_128_GCM]
        else
          @encryption_algorithm = RubySMB::SMB2::EncryptionCapabilities::ENCRYPTION_ALGORITM_MAP[RubySMB::SMB2::EncryptionCapabilities::AES_128_CCM]
        end
        update_preauth_hash(request_packet)
        update_preauth_hash(response_packet)
      end

      # Create a {RubySMB::SMB1::Packet::NegotiateRequest} packet with the
      # dialects filled in based on the protocol options set on the Client.
      #
      # @return [RubySMB::SMB1::Packet::NegotiateRequest] a completed SMB1 Negotiate Request packet
      def smb1_negotiate_request
        packet = RubySMB::SMB1::Packet::NegotiateRequest.new
        # Default to always enabling Extended Security. It simplifies the Negotiation process
        # while being guaranteed to work with any modern Windows system. We can get more sophisticated
        # with switching this on and off at a later date if the need arises.
        packet.smb_header.flags2.extended_security = 1
        # There is no real good reason to ever send an SMB1 Negotiate packet
        # to Negotiate strictly SMB2, but the protocol WILL support it
        packet.add_dialect(SMB1_DIALECT_SMB1_DEFAULT) if smb1
        packet.add_dialect(SMB1_DIALECT_SMB2_DEFAULT) if smb2
        packet.add_dialect(SMB1_DIALECT_SMB2_WILDCARD) if smb3
        packet
      end

      # Create a {RubySMB::SMB2::Packet::NegotiateRequest} packet with
      # the default dialect added. This will never be used when we
      # may want to communicate over SMB1
      #
      # @ return [RubySMB::SMB2::Packet::NegotiateRequest] a completed SMB2 Negotiate Request packet
      def smb2_negotiate_request
        packet = RubySMB::SMB2::Packet::NegotiateRequest.new
        packet.security_mode.signing_enabled = 1
        packet.add_dialect(SMB2_DIALECT_DEFAULT)
        packet.client_guid = SecureRandom.random_bytes(16)
        packet
      end

      def smb3_negotiate_request
        packet = RubySMB::SMB2::Packet::NegotiateRequest.new
        packet.security_mode.signing_enabled = 1
        packet.add_dialect(SMB3_DIALECT_DEFAULT)
        packet.client_guid = SecureRandom.random_bytes(16)

        nc = RubySMB::SMB2::NegotiateContext.new(
          context_type: RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        )
        nc.data.hash_algorithms << RubySMB::SMB2::PreauthIntegrityCapabilities::SHA_512
        nc.data.salt = SecureRandom.random_bytes(32)
        packet.add_negotiate_context(nc)

        if @encryption_required
          @preauth_integrity_hash_value = "\x00" * 64
          packet.capabilities.encryption = 1
          nc = RubySMB::SMB2::NegotiateContext.new(
            context_type: RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES
          )
          nc.data.ciphers << RubySMB::SMB2::EncryptionCapabilities::AES_128_CCM
          nc.data.ciphers << RubySMB::SMB2::EncryptionCapabilities::AES_128_GCM
          packet.add_negotiate_context(nc)
        end

        if @compression_required
          nc = RubySMB::SMB2::NegotiateContext.new(
            context_type: RubySMB::SMB2::NegotiateContext::SMB2_COMPRESSION_CAPABILITIES
          )
          nc.data.compression_algorithms << RubySMB::SMB2::CompressionCapabilities::NONE
          packet.negotiate_context_list << nc
        end

        packet
      end
    end
  end
end
