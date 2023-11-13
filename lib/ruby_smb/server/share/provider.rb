module RubySMB
  class Server
    module Share
      module Provider
        # The share provider defines the share and its attributes such as its
        # type and name. It is shared across all client connections and
        # sessions.
        class Base
          Hook = Struct.new(:request_class, :location, :callback)

          # @param [String] name The name of this share.
          def initialize(name, hooks: nil)
            @name = name
            @hooks = hooks || []
          end

          # Add a hook to be called when the specified request class is processed. Any hook that was previously
          # installed for the request class and location will be removed. A hook installed with a location of :before
          # will be called with the session and request as the only two arguments. The return value, if provided, will
          # replace the request that is to be processed. A hook installed with a location of :after will be called with
          # the session, request and response as the only three arguments. The return value, if provided, will replace
          # the response that is to be sent to the client.
          #
          # @param [RubySMB::GenericPacket] request_class The request class to register the hook for.
          # @param [Proc] callback The routine to be executed when the request class is being processed.
          # @param [Symbol] location When the callback should be invoked. Must be either :before or :after.
          def add_hook(request_class, callback: nil, location: :before, &block)
            unless %i[ before after ].include?(location)
              raise ArgumentError, 'the location argument must be :before or :after'
            end

            unless callback.nil? ^ block.nil?
              raise ArgumentError, 'either a callback or a block must be specified'
            end

            # Remove any hooks that were previously installed, this enforces that only one hook can be present at a time
            # for any particular request class and location combination.
            remove_hook(request_class, location: location)
            @hooks << Hook.new(request_class, location, callback || block)

            nil
          end

          # Remove a hook for the specified request class.
          #
          # @param [RubySMB::GenericPacket] request_class The request class to register the hook for.
          # @param [Symbol] location When the callback should be invoked.
          def remove_hook(request_class, location: :before)
            @hooks.filter! do |hook|
              hook.request_class == request_class && hook.location == location
            end

            nil
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

          # The hooks installed for this share.
          # @!attribute [r] hooks
          #   @return [Array]
          attr_accessor :hooks
        end
      end
    end
  end
end

require 'ruby_smb/server/share/provider/disk'
require 'ruby_smb/server/share/provider/pipe'
require 'ruby_smb/server/share/provider/virtual_disk'
