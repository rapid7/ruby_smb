module RubySMB
  class Server
    module Share
      TYPE_DISK = :disk
      TYPE_PIPE = :pipe
      TYPE_PRINT = :print
    end
  end
end

require 'ruby_smb/server/share/provider'
