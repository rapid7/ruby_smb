require 'ruby_smb/server/share/provider/disk/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          TYPE = TYPE_DISK

          def initialize(name, path)
            path = Pathname.new(File.expand_path(path))
            raise ArgumentError unless path.directory?
            @path = path
            super(name)
          end

          attr_accessor :path
        end
      end
    end
  end
end
