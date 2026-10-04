module RubySMB
  module Gss
    module Provider
      #
      # A GSS provider that offers more than one authentication mechanism to the client and routes each request to
      # whichever of its sub-providers understands the mechanism the client selected.
      #
      # SPNEGO exists so that a client and server can agree on a mechanism, but a server that only ever advertises one
      # has nothing to negotiate. This provider advertises the mechanisms of every provider it holds, in the order they
      # were given, so a client can pick the one it prefers.
      #
      # @example Offer Kerberos, falling back to NTLM
      #   provider = RubySMB::Gss::Provider::Multi.new([kerberos_provider, ntlm_provider])
      #   RubySMB::Server.new(gss_provider: provider)
      #
      class Multi < Base
        #
        # @param [Array<Provider::Base>] providers the providers to offer, in preference order (most preferred first).
        def initialize(providers)
          raise ArgumentError, 'at least one provider is required' if providers.nil? || providers.empty?

          @providers = providers.dup.freeze
        end

        # @return [Array<Provider::Base>] the providers this instance will route between.
        attr_reader :providers

        def new_authenticator(server_client)
          Authenticator.new(self, server_client)
        end

        #
        # Every mechanism offered by every provider, in provider order, with duplicates removed so a mechanism supported
        # by two providers is only advertised once.
        #
        # @return [Array<OpenSSL::ASN1::ObjectId>]
        def mech_types
          @providers.flat_map(&:mech_types).uniq(&:oid)
        end

        #
        # The first provider that handles the specified mechanism, or nil if none do.
        #
        # @param [OpenSSL::ASN1::ObjectId] mech_type the mechanism selected by the client
        # @return [Provider::Base, nil]
        def provider_for(mech_type)
          @providers.find { |provider| provider.supports_mech_type?(mech_type) }
        end

        def allow_anonymous
          @providers.any?(&:allow_anonymous)
        end

        def allow_guests
          @providers.any?(&:allow_guests)
        end

        class Authenticator < Authenticator::Base
          # The derivation strings MS-NLMP uses to turn the NTLM exported session key into the
          # one-way signing and sealing keys for the client-to-server direction. The mechListMIC
          # is signed with the client-to-server signing key (seq=0), optionally RC4-whitened with
          # the sealing key when NEGOTIATE_KEY_EXCHANGE was agreed.
          NTLM_C2S_SIGNING_CONSTANT = "session key to client-to-server signing key magic constant\0".b.freeze
          NTLM_C2S_SEALING_CONSTANT = "session key to client-to-server sealing key magic constant\0".b.freeze

          def initialize(provider, server_client)
            # built lazily, so a provider that is advertised but never selected is never instantiated
            @authenticators = {}
            @selected = nil
            @mech_list_der = nil
            @mech_mismatch_fired = false
            super
          end

          def reset!
            super
            @authenticators&.each_value(&:reset!)
            @selected = nil
            @mech_list_der = nil
            @mech_mismatch_fired = false
          end

          def process(request_buffer=nil)
            # the advertisement, listing every mechanism the server is willing to accept
            return Result.new(Gss.gss_neg_token_init(@provider.mech_types), WindowsError::NTStatus::STATUS_SUCCESS) if request_buffer.nil?

            begin
              gss_api = OpenSSL::ASN1.decode(request_buffer)
            rescue OpenSSL::ASN1::ASN1Error => e
              logger.error("Failed to parse the ASN1-encoded authentication request (#{e.message})")
              return
            end

            if negotiation_init?(gss_api)
              # a NegTokenInit carries the client's full mechTypeList. Server preference wins the
              # routing: the server picks its most-preferred advertised mechanism that the client
              # also offers, independent of the client's own ordering. This prevents a client (or
              # an on-path attacker rewriting the mechTypeList before signing is in effect) from
              # forcing the server to a weaker sub-provider by listing it first.
              client_oids = client_mech_oids(gss_api)
              if client_oids.empty?
                logger.warn('NegTokenInit carried no mechTypeList')
                return
              end

              # Remember the raw DER of the mechTypeList SEQUENCE for later mechListMIC
              # verification. Both sides compute GSS_GetMIC over these same bytes, so any on-path
              # change to the list between the client and the server will produce a mismatched MIC.
              @mech_list_der = Gss.asn1dig(gss_api, 1, 0, 0, 0)&.to_der

              chosen_mech = @provider.mech_types.find { |m| client_oids.include?(m.value) }
              if chosen_mech.nil?
                logger.warn("Client offered no mechanism the server supports (client_oids=#{client_oids})")
                return
              end

              @selected = authenticator_for(chosen_mech)

              # if the client listed a different mechanism first, its optimistic mechToken is for
              # the wrong mechanism. RFC 4178 section 4.2.2 says to reply with a NegTokenResp
              # carrying accept-incomplete and supportedMech so the client resends a token for the
              # mechanism the server selected
              if client_oids.first != chosen_mech.value
                @mech_mismatch_fired = true
                logger.info("SPNEGO: client listed #{client_oids.first} first; server prefers #{chosen_mech.value}, requesting a token for it")
                return Result.new(build_accept_incomplete(chosen_mech), WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED)
              end
            elsif @selected.nil?
              # a NegTokenResp carries no mechanism OID, so it can only be interpreted as a continuation of a
              # negotiation that has already selected one
              logger.warn('Received a GSS continuation token before any mechanism was selected')
              return
            end

            result = @selected.process(request_buffer)

            # Verify the client's mechListMIC on the leg that completes authentication. The MIC
            # proves the client's own view of the mechTypeList matches what the server saw, so an
            # on-path attacker who dropped or reordered OIDs between the two cannot pass this
            # check without the negotiated mechanism's session key.
            #
            # Microsoft's [MS-SPNG] section 3.2.5.5 requires the client to carry a mechListMIC
            # whenever the mechanism the server selected is not the one the client listed first,
            # which is the exact code path we take when accept-incomplete fired above. For the
            # happy path, the MIC is optional, and we verify when present but do not require it.
            if result.is_a?(Result) && result.nt_status == WindowsError::NTStatus::STATUS_SUCCESS && @selected.is_a?(RubySMB::Gss::Provider::NTLM::Authenticator)
              session_key = @selected.session_key
              mic = extract_mech_list_mic(gss_api)
              if mic.nil?
                if @mech_mismatch_fired
                  logger.warn('mechListMIC is required on the mismatch path (MS-SPNG 3.2.5.5) but was not present; rejecting')
                  return Result.new(nil, WindowsError::NTStatus::STATUS_LOGON_FAILURE)
                end
                # optimistic path: MIC is OPTIONAL per RFC 4178, nothing more to do
              elsif !verify_ntlm_mech_list_mic(mic, session_key)
                logger.warn('mechListMIC verification failed; rejecting authentication')
                return Result.new(nil, WindowsError::NTStatus::STATUS_LOGON_FAILURE)
              else
                logger.info('mechListMIC verified against the mechTypeList the server observed')
              end
            end

            result
          end

          # The session key belongs to whichever mechanism actually authenticated the client.
          def session_key
            @selected&.session_key
          end

          def session_key=(value)
            @selected&.session_key = value
          end

          private

          # Whether the token is a NegTokenInit, which is the only token that names a mechanism.
          def negotiation_init?(gss_api)
            gss_api&.tag == 0 && gss_api&.tag_class == :APPLICATION
          end

          def authenticator_for(mech_type)
            provider = @provider.provider_for(mech_type)
            return nil if provider.nil?

            @authenticators[provider] ||= provider.new_authenticator(@server_client)
          end

          # The OIDs the client listed in the NegTokenInit mechTypeList, in the client's own order.
          #
          # The ASN.1 path mirrors the one NTLM uses to reach a single mechTypeList entry
          # (gss_api, 1, 0, 0, 0, 0): one level less reaches the Sequence that holds every entry.
          def client_mech_oids(gss_api)
            seq = Gss.asn1dig(gss_api, 1, 0, 0, 0)
            return [] unless seq.respond_to?(:value) && seq.value.is_a?(Array)

            seq.value.map { |item| item.respond_to?(:value) ? item.value : nil }.compact
          end

          # A NegTokenResp carrying negResult = accept-incomplete and supportedMech, per RFC 4178
          # section 4.2.2, used to request a mechToken for the mechanism the server selected when
          # the client's optimistic mechToken was for a different mechanism.
          def build_accept_incomplete(supported_mech)
            OpenSSL::ASN1::ASN1Data.new([
              OpenSSL::ASN1::Sequence.new([
                OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Enumerated.new(OpenSSL::BN.new(1))], 0, :CONTEXT_SPECIFIC),
                OpenSSL::ASN1::ASN1Data.new([supported_mech], 1, :CONTEXT_SPECIFIC)
              ])
            ], 1, :CONTEXT_SPECIFIC).to_der
          end

          # Pull the mechListMIC octet string out of the client's NegTokenResp. The NegTokenInit
          # path also allows a mechListMIC at tag [3] but is unusual, so both shapes are handled.
          def extract_mech_list_mic(gss_api)
            seq = case gss_api&.tag_class
                  when :APPLICATION   then Gss.asn1dig(gss_api, 1, 0)
                  when :CONTEXT_SPECIFIC then Gss.asn1dig(gss_api, 0)
                  end
            return nil unless seq.respond_to?(:value) && seq.value.is_a?(Array)

            seq.value.each do |element|
              next unless element.respond_to?(:tag) && element.tag == 3 && element.tag_class == :CONTEXT_SPECIFIC
              inner = element.value.is_a?(Array) ? element.value[0] : nil
              return inner&.value
            end
            nil
          end

          # Verify an NTLM-generated mechListMIC. The MIC is the 16-byte MS-NLMP 3.4.4.2 signature:
          # version 1 (4 bytes LE), 8 bytes of HMAC-MD5 keyed by the client-to-server signing key
          # over the concatenation of the sequence number and the mechTypeList DER bytes, and the
          # sequence number itself (4 bytes LE). When NEGOTIATE_KEY_EXCHANGE was agreed, the HMAC
          # bytes are additionally RC4-whitened under the client-to-server sealing key.
          def verify_ntlm_mech_list_mic(mic, session_key)
            return false unless @mech_list_der && session_key && mic.respond_to?(:bytesize) && mic.bytesize == 16

            version = mic.byteslice(0, 4)
            checksum = mic.byteslice(4, 8)
            seqnum = mic.byteslice(12, 4)
            return false unless version == "\x01\x00\x00\x00".b

            sign_key = OpenSSL::Digest::MD5.digest(session_key + NTLM_C2S_SIGNING_CONSTANT)
            expected = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, sign_key, seqnum + @mech_list_der).byteslice(0, 8)

            # Try the straight comparison first (the client did not negotiate key exchange, or the
            # sealing step was skipped). If that fails and RC4 is available, apply the whitening
            # NEGOTIATE_KEY_EXCHANGE adds and compare again. One of the two matches when the MIC
            # was produced by a client that holds the same session key.
            return true if OpenSSL.secure_compare(expected, checksum)

            begin
              seal_key = OpenSSL::Digest::MD5.digest(session_key + NTLM_C2S_SEALING_CONSTANT)
              rc4 = OpenSSL::Cipher.new('rc4')
              rc4.encrypt
              rc4.key = seal_key
              whitened = rc4.update(expected) + rc4.final
              OpenSSL.secure_compare(whitened, checksum)
            rescue OpenSSL::Cipher::CipherError
              # OpenSSL 3 with the legacy provider off has no RC4; a MIC signed under
              # NEGOTIATE_KEY_EXCHANGE cannot be verified here, so treat it as a mismatch
              # rather than silently accepting.
              false
            end
          rescue => e
            logger.error("mechListMIC verification raised #{e.class}: #{e.message}")
            false
          end
        end
      end
    end
  end
end
