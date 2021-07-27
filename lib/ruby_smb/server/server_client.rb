module RubySMB
  class Server
    class ServerClient
      def initialize(server, dispatcher)
        @server = server
        @dispatcher = dispatcher
        @state = :negotiating
      end

      def run
        loop do
          raw_data = recv_packet

          case @state
          when :negotiating
            handle_negotiation(raw_data)
          end

          break if @dispatcher.tcp_socket.closed?
        end
      end

      def disconnect!
        @dispatcher.tcp_socket.close
      end

      private

      def build_gss_api
        # this is only NTLMSSP (as opposed to SPNEGO + NTLMSSP)
        OpenSSL::ASN1::ASN1Data.new([
          Gss::OID_SPNEGO,
          OpenSSL::ASN1::ASN1Data.new([
            OpenSSL::ASN1::Sequence.new([
              OpenSSL::ASN1::ASN1Data.new([
                OpenSSL::ASN1::Sequence.new([
                  Gss::OID_NTLMSSP
                ])
              ], 0, :CONTEXT_SPECIFIC),
              OpenSSL::ASN1::ASN1Data.new([
                OpenSSL::ASN1::ASN1Data.new([
                  OpenSSL::ASN1::ASN1Data.new([
                    OpenSSL::ASN1::GeneralString.new('not_defined_in_RFC4178@please_ignore')
                  ], 0, :CONTEXT_SPECIFIC)
                ], 16, :UNIVERSAL)
              ], 3, :CONTEXT_SPECIFIC)
            ])
          ], 0, :CONTEXT_SPECIFIC)
        ], 0, :APPLICATION)
      end

      def recv_packet
        @dispatcher.recv_packet
      end

      def send_packet(packet)
        @dispatcher.send_packet(packet)
      end

      def handle_negotiation(packet)
        case packet[0...4]
        when "\xff\x53\x4d\x42".b
          handle_negotiation_smb1(packet)
        when "\xfe\x53\x4d\x42".b
          handle_negotiation_smb2(packet)
        else
          disconnect!
        end
      end

      def handle_negotiation_smb1(raw_request)
        request = SMB1::Packet::NegotiateRequest.read(raw_request)

        unless request.dialects.map(&:dialect_string).include?(Client::SMB1_DIALECT_SMB2_WILDCARD)
          # SMB1 is not supported yet
          response = SMB1::Packet::NegotiateResponse.new
          response.parameter_block.word_count = 1
          response.parameter_block.dialect_index = 0xffff
          response.data_block.byte_count = 0
          send_packet(response)
          disconnect!
          return
        end

        response = SMB2::Packet::NegotiateResponse.new
        response.smb2_header.credits = 1
        response.security_mode.signing_enabled = 1
        response.dialect_revision = 0x02ff
        response.server_guid = @server.server_guid

        response.max_transact_size = 0x800000
        response.max_read_size = 0x800000
        response.max_write_size = 0x800000
        response.system_time.set(Time.now)
        response.security_buffer_offset = response.security_buffer.abs_offset
        response.security_buffer = gss_api.to_der

        send_packet(response)
      end

      def handle_negotiation_smb2(raw_request)
        request = SMB2::Packet::NegotiateRequest.read(raw_request)

        dialect = ([0x311, 0x302, 0x300, 0x210, 0x202] & request.dialects.map(&:to_i)).sort.last
        if dialect.nil?
          # todo: respond with an appropriate error when no dialect is supported
          disconnect!
          return
        end

        response = SMB2::Packet::NegotiateResponse.new
        response.smb2_header.credits = 1
        response.security_mode.signing_enabled = 1
        response.dialect_revision = dialect
        response.server_guid = @server.server_guid

        response.max_transact_size = 0x800000
        response.max_read_size = 0x800000
        response.max_write_size = 0x800000
        response.system_time.set(Time.now)

        response.security_buffer_offset = response.security_buffer.abs_offset
        response.security_buffer = build_gss_api.to_der

        response.negotiate_context_offset = response.negotiate_context_list.abs_offset
        response.add_negotiate_context(SMB2::NegotiateContext.new(
          context_type: SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
          data: SMB2::PreauthIntegrityCapabilities.new(
            hash_algorithms: [ SMB2::PreauthIntegrityCapabilities::SHA_512 ],
            salt: SecureRandom.random_bytes(32))
        ))
        response.add_negotiate_context(SMB2::NegotiateContext.new(
          context_type: SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES,
          data: SMB2::EncryptionCapabilities.new(
            # todo: Windows Server 2019 only returns AES-128-CCM but we should support GCM too
            ciphers: [ SMB2::EncryptionCapabilities::AES_128_CCM ]
          )
        ))

        send_packet(response)
      end
    end
  end
end
