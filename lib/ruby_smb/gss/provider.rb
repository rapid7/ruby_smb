module RubySMB
  module Gss
    #
    # This module provides GSS based authentication.
    #
    module Provider
      # A special constant implying that the authenticated user is anonymous.
      IDENTITY_ANONYMOUS = :anonymous
      # The result of a processed GSS request.
      Result = Struct.new(:buffer, :nt_status, :identity)

      #
      # The base class for a GSS authentication provider. This class defines a common interface and is not usable as a
      # provider on its own.
      #
      class Base
        # Create a new, client-specific authenticator instance. This new instance is then able to track the unique state
        # of a particular client / connection.
        #
        # @param [Server::ServerClient] server_client the client instance that this the authenticator will be for
        def new_authenticator(server_client)
          raise NotImplementedError
        end

        #
        # Whether or not anonymous authentication attempts should be permitted.
        #
        attr_accessor :allow_anonymous
      end
    end
  end
end

require 'ruby_smb/gss/provider/authenticator'
require 'ruby_smb/gss/provider/ntlm'
