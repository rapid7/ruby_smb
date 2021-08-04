module RubySMB
  module Gss
    module Provider
      module Authenticator
        class Base
          def initialize(provider, server_client)
            @provider = provider
            @server_client = server_client
            @session_key = nil
            reset!
          end

          def process(request_buffer)
            raise NotImplementedError
          end

          def reset!
            @session_key = nil
          end

          attr_accessor :session_key
        end
      end
    end
  end
end
