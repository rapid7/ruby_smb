module RubySMB
  module Gss
    module Provider
      Account = Struct.new(:username, :password, :domain)
      Result = Struct.new(:buffer, :nt_status)

      class Base
        def new_processor(server_client)
          raise NotImplementedError
        end
      end
    end
  end
end

require 'ruby_smb/gss/provider/processor'
require 'ruby_smb/gss/provider/ntlm'
