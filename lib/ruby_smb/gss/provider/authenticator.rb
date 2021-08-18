module RubySMB
  module Gss
    module Provider
      module Authenticator
        #
        # The base class for a GSS provider's unique authenticator. This provides a common interface and is not usable
        # on it's own. The provider-specific authentication logic is defined within this authenticator class which
        # actually runs the authentication routine.
        #
        class Base
          # @param [Provider::Base] provider the GSS provider that this instance is an authenticator for
          # @param server_client the client instance that this will be an authenticator for
          def initialize(provider, server_client)
            @provider = provider
            @server_client = server_client
            @session_key = nil
            reset!
          end

          #
          # Process a GSS authentication buffer. If no buffer is specified, the request is assumed to be the first in
          # the negotiation sequence.
          #
          # @param [String, nil] buffer the request GSS request buffer that should be processed
          # @return [Gss::Provider::Result] the result of the processed GSS request
          def process(request_buffer=nil)
            raise NotImplementedError
          end

          #
          # Reset the authenticator's state, wiping anything related to a partial or complete authentication process.
          #
          def reset!
            @session_key = nil
          end

          attr_accessor :session_key
        end
      end
    end
  end
end
