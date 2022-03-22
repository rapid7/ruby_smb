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
          response = nil
          case raw_request[0...4].unpack1('L>')
          when RubySMB::SMB1::SMB_PROTOCOL_ID
            request = SMB1::Packet::NegotiateRequest.read(raw_request)
            response = do_negotiate_smb1(request) if request.is_a?(SMB1::Packet::NegotiateRequest)
          when RubySMB::SMB2::SMB2_PROTOCOL_ID
            request = SMB2::Packet::NegotiateRequest.read(raw_request)
            response = do_negotiate_smb2(request) if request.is_a?(SMB2::Packet::NegotiateRequest)
          end

          if response.nil?
            disconnect!
          else
            send_packet(response)
          end

          nil
        end

        def do_negotiate_smb1(request)
          client_dialects = request.dialects.map(&:dialect_string).map(&:value)

          if client_dialects.include?(Client::SMB1_DIALECT_SMB2_WILDCARD) && \
              @server.dialects.any? { |dialect| Dialect[dialect].order == Dialect::ORDER_SMB2 }
            response = SMB2::Packet::NegotiateResponse.new
            response.smb2_header.credits = 1
            response.security_mode.signing_enabled = 1
            response.dialect_revision = SMB2::SMB2_WILDCARD_REVISION
            response.server_guid = @server.guid

            response.max_transact_size = 0x800000
            response.max_read_size = 0x800000
            response.max_write_size = 0x800000
            response.system_time.set(Time.now)
            response.security_buffer_offset = response.security_buffer.abs_offset
            response.security_buffer = process_gss.buffer
            return response
          end

          server_dialects = @server.dialects.select { |dialect| Dialect[dialect].order == Dialect::ORDER_SMB1 }
          dialect = (server_dialects & client_dialects).first
          if dialect.nil?
            # 'NT LM 0.12' is currently the only supported dialect
            # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/80850595-e301-4464-9745-58e4945eb99b
            response = SMB1::Packet::NegotiateResponse.new
            response.parameter_block.word_count = 1
            response.parameter_block.dialect_index = 0xffff
            response.data_block.byte_count = 0
            return response
          end

          response = SMB1::Packet::NegotiateResponseExtended.new
          response.parameter_block.dialect_index = client_dialects.index(dialect)
          response.parameter_block.max_mpx_count = 50
          response.parameter_block.max_number_vcs = 1
          response.parameter_block.max_buffer_size = 16644
          response.parameter_block.max_raw_size = 65536
          server_time = Time.now
          response.parameter_block.system_time.set(server_time)
          response.parameter_block.server_time_zone = server_time.utc_offset
          response.data_block.server_guid = @server.guid
          response.data_block.security_blob = process_gss.buffer

          @dialect = dialect
          response
        end

        def do_negotiate_smb2(request)
          client_dialects = request.dialects.map { |d| "0x%04x" % d }
          server_dialects = @server.dialects.select { |dialect| Dialect[dialect].order == Dialect::ORDER_SMB2 }
          dialect = (server_dialects & client_dialects).first

          response = SMB2::Packet::NegotiateResponse.new
          response.smb2_header.credits = 1
          response.smb2_header.message_id = request.smb2_header.message_id
          response.security_mode.signing_enabled = 1
          response.server_guid = @server.guid
          response.max_transact_size = 0x800000
          response.max_read_size = 0x800000
          response.max_write_size = 0x800000
          response.system_time.set(Time.now)
          if dialect.nil?
            # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1
            # > If a common dialect is not found, the server MUST fail the request with STATUS_NOT_SUPPORTED.
            response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NOT_SUPPORTED.value
            return response
          end

          contexts = []
          hash_algorithm = hash_value = nil
          if dialect == '0x0311'
            # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1
            nc = request.find_negotiate_context(SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
            hash_algorithm = SMB2::PreauthIntegrityCapabilities::HASH_ALGORITM_MAP[nc&.data&.hash_algorithms&.first]
            hash_value = "\x00" * 64
            unless hash_algorithm
              response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_PARAMETER.value
              return response
            end

            contexts << SMB2::NegotiateContext.new(
              context_type: SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
              data: {
                hash_algorithms: [ SMB2::PreauthIntegrityCapabilities::SHA_512 ],
                salt: SecureRandom.random_bytes(32)
              }
            )

            nc = request.find_negotiate_context(SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES)
            cipher = nc&.data&.ciphers&.first
            if SMB2::EncryptionCapabilities::ENCRYPTION_ALGORITHM_MAP.include? cipher
              @cipher_id = cipher
            else
              cipher = 0
            end
            contexts << SMB2::NegotiateContext.new(
              context_type: SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES,
              data: {
                ciphers: [ cipher ]
              }
            )
          elsif dialect == '0x0300' || dialect == '0x0302'
            if request.capabilities.encryption == 1
              response.capabilities.encryption = 1
              @cipher_id = SMB2::EncryptionCapabilities::AES_128_CCM
            else
              response.capabilities = 0
            end
          end

          # the order in which the response is built is important to ensure it is valid
          response.dialect_revision = dialect.to_i(16)
          response.security_buffer_offset = response.security_buffer.abs_offset
          response.security_buffer = process_gss.buffer
          if dialect == '0x0311'
            response.negotiate_context_offset = response.negotiate_context_list.abs_offset
            contexts.each { |nc| response.add_negotiate_context(nc) }
          end
          @preauth_integrity_hash_algorithm = hash_algorithm
          @preauth_integrity_hash_value = hash_value

          if dialect == '0x0311'
            update_preauth_hash(request)
            update_preauth_hash(response)
          end

          @dialect = dialect
          response
        end
      end
    end
  end
end
