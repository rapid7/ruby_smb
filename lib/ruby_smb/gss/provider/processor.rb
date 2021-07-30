module RubySMB
  module Gss
    module Provider
      module Processor
        class Base
          def initialize(provider, server_client)
            @provider = provider
            @server_client = server_client
            reset!
          end

          def process(request_buffer)
            raise NotImplementedError
          end

          def reset!
          end
        end
      end
    end
  end
end
