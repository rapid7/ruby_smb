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
            path = Pathname.new(File.expand_path(path)) if path.is_a?(String)
            raise ArgumentError.new('path must be a directory') unless path.directory? # it needs to exist
            raise ArgumentError.new('path must be absolute') unless path.absolute? # it needs to be absolute so it is independent of the cwd

            @path = path
            super(name)
          end

          attr_accessor :path
        end
      end
    end
  end
end
