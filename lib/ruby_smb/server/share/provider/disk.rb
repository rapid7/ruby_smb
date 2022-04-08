require 'ruby_smb/server/share/provider/disk/file_system'
require 'ruby_smb/server/share/provider/disk/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          TYPE = TYPE_DISK
          # emulate NTFS just like Samba does
          FILE_SYSTEM = FileSystem::NTFS

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
