module RubySMB
  module Gss
    module Provider
      IDENTITY_ANONYMOUS = :anonymous
      Result = Struct.new(:buffer, :nt_status, :identity)

      class Base
        def new_authenticator(server_client)
          raise NotImplementedError
        end

        attr_accessor :allow_anonymous
      end
    end
  end
end

require 'ruby_smb/gss/provider/authenticator'
require 'ruby_smb/gss/provider/ntlm'
