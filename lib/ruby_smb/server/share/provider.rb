module RubySMB
  class Server
    module Share
      module Provider
        # The share provider defines the share and its attributes such as its
        # type and name. It is shared across all client connections and
        # sessions.
        class Base
          # @param [String] name The name of this share.
          def initialize(name)
            @name = name
          end

          # Create a new, session-specific processor instance for this share.
          #
          # @param [RubySMB::Server::ServerClient] server_client The client connection.
          # @param [RubySMB::Server::Session] session The session object.
          def new_processor(server_client, session)
            self.class::Processor.new(self, server_client, session)
          end

          # The type of this share.
          def type
            self.class::TYPE
          end

          # The name of this share.
          # @!attribute [r] name
          #   @return [String]
          attr_accessor :name
        end
      end
    end
  end
end

require 'ruby_smb/server/share/provider/disk'
require 'ruby_smb/server/share/provider/pipe'
