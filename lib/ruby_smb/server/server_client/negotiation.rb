require 'securerandom'

module RubySMB
  class Server
    class ServerClient
      module Negotiation
        #
        # Handle an SMB negotiation request. Once negotiation is complete, the state will be updated to :session_setup.
        # At this point the @dialect will have been set along with other dialect-specific values.
        #
        # @param [String] raw_request the negotiation request to process
        def handle_negotiate(raw_request)
          case raw_request[0...4]
          when "\xff\x53\x4d\x42".b
            handle_negotiate_smb1(raw_request)
          when "\xfe\x53\x4d\x42".b
            handle_negotiate_smb2(raw_request)
          else
            disconnect!
          end
        end

        def handle_negotiate_smb1(raw_request)
          request = SMB1::Packet::NegotiateRequest.read(raw_request)

          if request.dialects.map(&:dialect_string).include?(Client::SMB1_DIALECT_SMB2_WILDCARD)
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
            response.security_buffer = process_gss.buffer

            send_packet(response)
            return
          end

          dialect_strings = request.dialects.map(&:dialect_string).map(&:value)
          dialect = (['NT LM 0.12'] & dialect_strings).first
          if dialect.nil?
            # 'NT LM 0.12' is currently the only supported dialect
            # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/80850595-e301-4464-9745-58e4945eb99b
            response = SMB1::Packet::NegotiateResponse.new
            response.parameter_block.word_count = 1
            response.parameter_block.dialect_index = 0xffff
            response.data_block.byte_count = 0
            send_packet(response)
            disconnect!
            return
          end

          response = SMB1::Packet::NegotiateResponseExtended.new
          response.parameter_block.dialect_index = dialect_strings.index(dialect)
          response.parameter_block.max_mpx_count = 50
          response.parameter_block.max_number_vcs = 1
          response.parameter_block.max_buffer_size = 16644
          response.parameter_block.max_raw_size = 65536
          server_time = Time.now
          response.parameter_block.system_time.set(Time.now)
          response.parameter_block.server_time_zone = server_time.utc_offset
          response.data_block.server_guid = @server.server_guid
          response.data_block.security_blob = process_gss.buffer

          @state = :session_setup
          @dialect = dialect
          send_packet(response)
        end

        def handle_negotiate_smb2(raw_request)
          request = SMB2::Packet::NegotiateRequest.read(raw_request)

          dialect = ([0x311, 0x302, 0x300, 0x210, 0x202] & request.dialects.map(&:to_i)).first

          response = SMB2::Packet::NegotiateResponse.new
          response.smb2_header.credits = 1
          response.security_mode.signing_enabled = 1
          response.server_guid = @server.server_guid
          response.max_transact_size = 0x800000
          response.max_read_size = 0x800000
          response.max_write_size = 0x800000
          response.system_time.set(Time.now)
          if dialect.nil?
            # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1
            # > If a common dialect is not found, the server MUST fail the request with STATUS_NOT_SUPPORTED.
            response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NOT_SUPPORTED.value
            send_packet(response)
            return
          end

          contexts = []
          hash_algorithm = hash_value = nil
          if dialect == 0x311
            # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1
            nc = request.find_negotiate_context(SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
            hash_algorithm = SMB2::PreauthIntegrityCapabilities::HASH_ALGORITM_MAP[nc&.data&.hash_algorithms&.first]
            hash_value = "\x00" * 64
            unless hash_algorithm
              response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_PARAMETER.value
              send_packet(response)
              return
            end

            contexts << SMB2::NegotiateContext.new(
              context_type: SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
              data: SMB2::PreauthIntegrityCapabilities.new(
                hash_algorithms: [ SMB2::PreauthIntegrityCapabilities::SHA_512 ],
                salt: SecureRandom.random_bytes(32))
            )

            nc = request.find_negotiate_context(SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES)
            cipher = nc&.data&.ciphers&.first
            cipher = 0 unless SMB2::EncryptionCapabilities::ENCRYPTION_ALGORITHM_MAP.include? cipher
            contexts << SMB2::NegotiateContext.new(
              context_type: SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES,
              data: SMB2::EncryptionCapabilities.new(
                ciphers: [ cipher ]
              )
            )
          end

          # the order in which the response is built is important to ensure it is valid
          response.dialect_revision = dialect
          response.security_buffer_offset = response.security_buffer.abs_offset
          response.security_buffer = process_gss.buffer
          if dialect == 0x311
            response.negotiate_context_offset = response.negotiate_context_list.abs_offset
            contexts.each { |nc| response.add_negotiate_context(nc) }
          end
          @preauth_integrity_hash_algorithm = hash_algorithm
          @preauth_integrity_hash_value = hash_value

          if dialect == 0x311
            update_preauth_hash(request)
            update_preauth_hash(response)
          end

          @state = :session_setup
          @dialect = "0x%04x" % dialect
          send_packet(response)
        end
      end
    end
  end
end
