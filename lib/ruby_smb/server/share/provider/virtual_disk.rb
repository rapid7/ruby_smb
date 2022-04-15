require 'ruby_smb/server/share/provider/disk'
require 'ruby_smb/server/share/provider/virtual_disk/virtual_file'
require 'ruby_smb/server/share/provider/virtual_disk/virtual_pathname'
require 'ruby_smb/server/share/provider/virtual_disk/virtual_stat'

module RubySMB
  class Server
    module Share
      module Provider
        class VirtualDisk < Disk
          def initialize(name)
            @vfs = {}
            super(name, add(VirtualPathname.new(self, File::SEPARATOR)))
          end

          def add_dynamic_file(path, content_size, stat: nil, pad: "\x00", &block)
            raise ArgumentError.new('a block must be specified for dynamic files') unless block_given?
            path = VirtualPathname.cleanpath(path)
            path = File::SEPARATOR + path unless path.start_with?(File::SEPARATOR)
            raise ArgumentError.new('must be a file') if stat && !stat.file?

            vf = VirtualDynamicFile.new(self, path, content_size, stat: stat, pad: pad)
            vf.generate_content(&block)
            add(vf)
          end

          def add_mapped_file(path, mapped_path)
            path = VirtualPathname.cleanpath(path)
            path = File::SEPARATOR + path unless path.start_with?(File::SEPARATOR)

            vf = VirtualMappedFile.new(self, path, mapped_path)
            add(vf)
          end

          def add_static_file(path, content, stat: nil)
            path = VirtualPathname.cleanpath(path)
            path = File::SEPARATOR + path unless path.start_with?(File::SEPARATOR)
            raise ArgumentError.new('must be a file') if stat && !stat.file?

            content = content.read if content.respond_to?(:read)
            vf = VirtualStaticFile.new(self, path, content, stat: stat)
            add(vf)
          end

          def add_static_fileobj(path, file_obj)
            add_static_file(path, file_obj, stat: file_obj.stat)
          end

          private

          def add(virtual_pathname)
            raise ArgumentError.new('paths must be absolute') unless virtual_pathname.absolute?

            path = virtual_pathname.to_s
            raise ArgumentError.new('paths must be normalized') unless VirtualPathname.cleanpath(path) == path

            path_parts = path.split(VirtualPathname::SEPARATOR)
            2.upto(path_parts.length - 1) do |idx|
              ancestor = path_parts[0...idx].join(path[VirtualPathname::SEPARATOR])
              next if @vfs[ancestor]&.directory?

              @vfs[ancestor] = VirtualPathname.new(self, ancestor, stat: VirtualStat.new(directory?: true))
            end

            @vfs[path] = virtual_pathname
          end

          def method_missing(symbol, *args)
            if %i[ [] each each_key each_value ].include?(symbol)
              return @vfs.send(symbol, *args)
            end

            raise NoMethodError, "undefined method `#{symbol}' for #{self.class}"
          end
        end
      end
    end
  end
end
