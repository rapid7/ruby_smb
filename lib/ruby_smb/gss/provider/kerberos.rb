module RubySMB
  module Gss
    module Provider
      #
      # A GSS provider that advertises Kerberos and surfaces the mechanism token a client sends, without interpreting
      # it.
      #
      # A Kerberos AP-REQ is encrypted to the service the client believes it is talking to, so a server that does not
      # hold that service's key cannot read it. This provider therefore does not attempt to: it hands the token to a
      # handler and lets that decide what to tell the client. That is enough for a server to observe or forward
      # Kerberos authentication, and it keeps Kerberos message parsing out of this library entirely.
      #
      # Accepting Kerberos properly, by decrypting the ticket with a service key and validating the PAC, is a separate
      # concern and is not implemented here.
      #
      # @example Capture the token a client sends
      #   provider = RubySMB::Gss::Provider::Kerberos.new
      #   provider.on_mech_token do |token, authenticator|
      #     # token is the opaque GSS mechanism token, starting with its two byte token id
      #     RubySMB::Gss::Provider::Result.new(nil, WindowsError::NTStatus::STATUS_LOGON_FAILURE)
      #   end
      #
      class Kerberos < Base
        # The GSS token identifiers that may prefix a Kerberos mechanism token, per RFC 4121 section 4.1. They are
        # provided so a handler can tell the messages apart without decoding the payload.
        TOK_ID_KRB_AP_REQ = "\x01\x00".b.freeze
        TOK_ID_KRB_AP_REP = "\x02\x00".b.freeze
        TOK_ID_KRB_ERROR  = "\x03\x00".b.freeze

        # @param [Proc, nil] block an optional handler for received mechanism tokens, see {#on_mech_token}.
        def initialize(&block)
          @on_mech_token = block
          @allow_anonymous = false
          @allow_guests = false
        end

        def new_authenticator(server_client)
          Authenticator.new(self, server_client)
        end

        def mech_types
          # both are advertised because Microsoft clients may select either
          [Gss::OID_KERBEROS_5, Gss::OID_MICROSOFT_KERBEROS_5]
        end

        #
        # Set or invoke the handler called when a client sends a Kerberos mechanism token.
        #
        # The handler receives the opaque token and the authenticator that received it, and returns the {Result} to
        # reply with. When no handler is set the authentication attempt is rejected, since this provider cannot
        # validate a ticket on its own.
        #
        # @param [String] token the mechanism token, as sent by the client
        # @param [Authenticator] authenticator the authenticator that received it
        # @return [Result, nil]
        def on_mech_token(token=nil, authenticator=nil, &block)
          if block.nil?
            return nil if @on_mech_token.nil?

            @on_mech_token.call(token, authenticator)
          else
            @on_mech_token = block
          end
        end

        class Authenticator < Authenticator::Base
          def reset!
            super
            @mech_token = nil
          end

          # @return [String, nil] the most recent mechanism token received from the client.
          attr_reader :mech_token

          def process(request_buffer=nil)
            if request_buffer.nil?
              return Result.new(Gss.gss_neg_token_init(@provider.mech_types), WindowsError::NTStatus::STATUS_SUCCESS)
            end

            begin
              gss_api = OpenSSL::ASN1.decode(request_buffer)
            rescue OpenSSL::ASN1::ASN1Error => e
              logger.error("Failed to parse the ASN1-encoded authentication request (#{e.message})")
              return
            end

            token = extract_mech_token(gss_api)
            if token.nil?
              logger.warn('Received a Kerberos request carrying no mechanism token')
              return
            end

            @mech_token = token
            result = @provider.on_mech_token(token, self)
            # with no handler there is nothing that can validate the ticket, so the attempt is refused rather than
            # silently succeeding
            result || Result.new(nil, WindowsError::NTStatus::STATUS_LOGON_FAILURE)
          end

          private

          #
          # Pull the mechanism token out of a SPNEGO NegTokenInit or NegTokenResp. The token is returned exactly as the
          # client sent it, so a caller that forwards it elsewhere does not alter the ticket it contains.
          #
          # @param gss_api the decoded request
          # @return [String, nil]
          def extract_mech_token(gss_api)
            if gss_api&.tag == 0 && gss_api&.tag_class == :APPLICATION
              # NegTokenInit: mechTypes then the mechToken
              Gss.asn1dig(gss_api, 1, 0, 1, 0)&.value
            elsif gss_api&.tag == 1 && gss_api&.tag_class == :CONTEXT_SPECIFIC
              # NegTokenResp: the responseToken, tagged 2, carries the continuation
              Hash[Gss.asn1dig(gss_api, 0)&.value.to_a.map { |obj| [obj.tag, obj.value[0].value] }][2]
            end
          end
        end
      end
    end
  end
end
