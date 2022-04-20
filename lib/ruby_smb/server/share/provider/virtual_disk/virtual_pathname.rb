module RubySMB
  class Server
    module Share
      module Provider
        class VirtualDisk < Disk
          # This object emulates Ruby's builtin Pathname object but uses a virtual file system instead of the real local
          # one.
          class VirtualPathname
            SEPARATOR = File::SEPARATOR
            # see: https://ruby-doc.org/stdlib-3.1.1/libdoc/pathname/rdoc/Pathname.html
            STAT_METHODS = %i[
              atime
              birthtime
              blockdev?
              chardev?
              ctime
              directory?
              executable?
              file?
              ftype
              grpowned?
              mtime
              owned?
              pipe?
              readable?
              setgid?
              setuid?
              size
              socket?
              sticky?
              symlink?
              world_readable?
              world_writable?
              writable?
              zero?
            ]
            private_constant :STAT_METHODS

            attr_accessor :virtual_disk

            # @param [Hash] disk The mapping of paths to objects representing the virtual file system.
            # @param [String] path The path of this entry.
            # @param [Boolean] exist? Whether or not this entry represents an existing entry in the virtual file system.
            # @param [File::Stat] stat An explicit stat that represents this object. A default VirtualStat will be
            #   created unless specified.
            def initialize(disk, path, **kwargs)
              @virtual_disk = disk
              @path = path

              if kwargs.fetch(:exist?, true)
                @stat = kwargs[:stat] || VirtualStat.new
              else
                raise ArgumentError.new('can not specify a stat object when exist? is false') if kwargs[:stat]
                @stat = nil
              end
            end

            def ==(other)
              other.is_a?(self.class) && other.to_s == to_s
            end

            def <=>(other)
              to_s <=> other.to_s
            end

            def exist?
              !@stat.nil?
            rescue Errno::ENOENT
              false
            end

            def stat
              raise Errno::ENOENT.new('No such file or directory') unless exist? && (@stat.file? || @stat.directory?)

              @stat
            end

            def join(other)
              # per the docs this Pathname#join doesn't touch the file system
              # see: https://ruby-doc.org/stdlib-3.1.1/libdoc/pathname/rdoc/Pathname.html#class-Pathname-label-Core+methods
              lookup_or_create(Pathname.new(to_s).join(other).to_s)
            end

            alias :+ :join
            alias :/ :join

            def to_s
              @path
            end

            def absolute?
              to_s.start_with?(SEPARATOR)
            end

            def relative?
              !absolute?
            end

            def basename
              lookup_or_create(self.class.basename(to_s))
            end

            def self.basename(*args)
              File.basename(*args)
            end

            def dirname
              lookup_or_create(self.class.dirname(to_s))
            end

            def self.dirname(*args)
              File.dirname(*args)
            end

            def extname
              File.extname(to_s)
            end

            def split
              [dirname, basename]
            end

            alias :parent :dirname

            def children(with_directory=true)
              raise Errno::ENOTDIR.new("Not a directory @ dir_initialize - #{to_s}") unless directory?

              @virtual_disk.each_value.select do |dirent|
                next if dirent == self
                next unless dirent.dirname == self

                with_directory ? dirent : dirent.basename
              end
            end

            def entries
              children(false)
            end

            def cleanpath(consider_symlink=false)
              lookup_or_create(self.class.cleanpath(to_s), stat: (exist? ? stat : nil))
            end

            def self.cleanpath(*args)
              # per the docs this Pathname#cleanpath doesn't touch the file system
              # see: https://ruby-doc.org/stdlib-3.1.1/libdoc/pathname/rdoc/Pathname.html#class-Pathname-label-Core+methods
              Pathname.new(*args).cleanpath.to_s
            end

            private

            # Check the virtual file system to see if the entry exists. Return it if it does, otherwise create a new
            # entry representing a non-existent path.
            #
            # @param [String] path The path to lookup in the virtual file system. It will be normalized using #cleanpath.
            # @return [Pathname] The path object representing the specified string.
            def lookup_or_create(path, **kwargs)
              existing = @virtual_disk[self.class.cleanpath(path)]
              return existing if existing

              kwargs[:exist?] = false
              @virtual_disk[self.class.cleanpath(path)] || VirtualPathname.new(@virtual_disk, path, **kwargs)
            end

            def method_missing(symbol, *args)
              # should we forward to one of the stat methods
              if STAT_METHODS.include?(symbol)
                # if we have a stat object then forward it
                return stat.send(symbol, *args) if exist?
                # if we don't have a stat object, emulate what Pathname does when it does not exist

                # these two methods return nil
                return nil if %i[ world_readable? world_writable? ].include?(symbol)

                # any of the other ?-suffixed methods return false
                return false if symbol.to_s.end_with?('?')

                # any other method raises a Errno::ENOENT exception
                raise Errno::ENOENT.new('No such file or directory')
              end

              raise NoMethodError, "undefined method `#{symbol}' for #{self.class}"
            end

            def respond_to_missing?(symbol, include_private = false)
              STAT_METHODS.include?(symbol)
            end
          end
        end
      end
    end
  end
end
