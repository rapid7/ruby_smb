require 'ruby_smb/server/share/provider/disk'
require 'ruby_smb/server/share/provider/virtual_disk/virtual_pathname'
require 'ruby_smb/server/share/provider/virtual_disk/virtual_stat'

module RubySMB
  class Server
    module Share
      module Provider
        class VirtualDisk < Disk
          def initialize(name)
            @path = nil
            super(name)
          end
        end
      end
    end
  end
end
