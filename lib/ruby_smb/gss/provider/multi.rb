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
          def initialize(provider, server_client)
            # built lazily, so a provider that is advertised but never selected is never instantiated
            @authenticators = {}
            @selected = nil
            super
          end

          def reset!
            super
            @authenticators&.each_value(&:reset!)
            @selected = nil
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
              # a NegTokenInit names the mechanism the client chose, so this is where routing is decided
              mech_type = Gss.asn1dig(gss_api, 1, 0, 0, 0, 0)
              authenticator = authenticator_for(mech_type)
              if authenticator.nil?
                logger.warn("Client selected an unsupported GSS mechanism (#{mech_type&.oid || 'unknown'})")
                return
              end

              @selected = authenticator
            elsif @selected.nil?
              # a NegTokenResp carries no mechanism OID, so it can only be interpreted as a continuation of a
              # negotiation that has already selected one
              logger.warn('Received a GSS continuation token before any mechanism was selected')
              return
            end

            @selected.process(request_buffer)
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
        end
      end
    end
  end
end
