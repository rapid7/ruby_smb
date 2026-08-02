module RubySMB
  module Gss
    #
    # This module provides GSS based authentication.
    #
    module Provider
      # A special constant implying that the authenticated user is anonymous.
      IDENTITY_ANONYMOUS = :anonymous
      # The result of a processed GSS request.
      Result = Struct.new(:buffer, :nt_status, :identity, :is_guest) do
        def is_anonymous
          identity == Gss::Provider::IDENTITY_ANONYMOUS
        end
      end

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
        # The GSS mechanisms this provider can handle, in preference order. These are advertised to the client in the
        # SPNEGO NegTokenInit, and are used to route an incoming token to the provider that understands it.
        #
        # @return [Array<OpenSSL::ASN1::ObjectId>]
        def mech_types
          raise NotImplementedError
        end

        #
        # Whether this provider can handle a token for the specified mechanism.
        #
        # @param [OpenSSL::ASN1::ObjectId] mech_type the mechanism selected by the client
        # @return [Boolean]
        def supports_mech_type?(mech_type)
          return false if mech_type.nil?

          mech_types.any? { |oid| oid.oid == mech_type.oid }
        end

        #
        # Whether or not anonymous authentication attempts should be permitted.
        #
        attr_accessor :allow_anonymous

        #
        # Whether or not unknown users should be allowed to authenticate as guests.
        #
        attr_accessor :allow_guests
      end
    end
  end
end

require 'ruby_smb/gss/provider/authenticator'
require 'ruby_smb/gss/provider/ntlm'
