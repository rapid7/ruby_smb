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
      # The token handed to the handler is the mechanism token exactly as the client sent it. For Kerberos that is a
      # GSS-API InitialContextToken (RFC 2743 section 3.1), which wraps the mechanism OID and the token identifier
      # around the Kerberos message:
      #
      #   60 82 0c 0e                 InitialContextToken
      #     06 09 2a 86 48 ..         the mechanism OID
      #     01 00                     the token id, here KRB_AP_REQ
      #     6e 82 0b fd ..            the AP-REQ itself
      #
      # Note that the token id follows the OID rather than starting the token, and that the framing around it is not
      # valid ASN.1, so OpenSSL::ASN1.decode will not parse it. {.token_id} reads it without decoding the payload.
      #
      # @example Capture the token a client sends
      #   provider = RubySMB::Gss::Provider::Kerberos.new
      #   provider.on_mech_token do |token, authenticator|
      #     RubySMB::Gss::Provider::Kerberos.token_id(token) == RubySMB::Gss::Provider::Kerberos::TOK_ID_KRB_AP_REQ
      #     RubySMB::Gss::Provider::Result.new(nil, WindowsError::NTStatus::STATUS_LOGON_FAILURE)
      #   end
      #
      class Kerberos < Base
        # The GSS token identifiers that may appear in a Kerberos mechanism token, per RFC 4121 section 4.1. They are
        # provided so a handler can tell the messages apart without decoding the payload.
        TOK_ID_KRB_AP_REQ = "\x01\x00".b.freeze
        TOK_ID_KRB_AP_REP = "\x02\x00".b.freeze
        TOK_ID_KRB_ERROR  = "\x03\x00".b.freeze

        #
        # Read the token identifier out of a GSS-API InitialContextToken, so a handler can tell an AP-REQ from an
        # AP-REP or a KRB-ERROR. The identifier follows the mechanism OID rather than starting the token, and the
        # framing is not valid ASN.1, so it is located by walking the lengths rather than by decoding.
        #
        # @param [String] token the mechanism token as received
        # @return [String, nil] the two byte identifier, or nil if the token is not shaped as expected
        def self.token_id(token)
          return nil if token.nil? || token.bytesize < 4 || token.getbyte(0) != 0x60

          length_byte = token.getbyte(1)
          # a long form length says how many bytes carry the length, a short form is the length itself
          offset = length_byte > 0x80 ? 2 + (length_byte & 0x7f) : 2
          return nil if token.getbyte(offset) != 0x06 # the mechanism OID must follow

          offset += 2 + token.getbyte(offset + 1)
          token.byteslice(offset, 2)
        end

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

            token = extract_mech_token(request_buffer)
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
          # @param [String] request_buffer the SPNEGO token as received
          # @return [String, nil]
          def extract_mech_token(request_buffer)
            # the identifier octet tells the two SPNEGO tokens apart: an InitialContextToken carrying a NegTokenInit is
            # tagged [APPLICATION 0], a NegTokenResp continuing an exchange is tagged [CONTEXT 1]
            case request_buffer.b.getbyte(0)
            when 0x60
              SpnegoNegTokenInit.parse(request_buffer).mech_token
            when 0xa1
              SpnegoNegTokenTarg.parse(request_buffer).response_token
            end
          rescue RASN1::ASN1Error => e
            logger.error("Failed to parse the SPNEGO token (#{e.message})")
            nil
          end
        end
      end
    end
  end
end
