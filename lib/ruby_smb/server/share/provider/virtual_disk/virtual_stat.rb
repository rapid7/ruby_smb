module RubySMB
  class Server
    module Share
      module Provider
        class VirtualDisk < Disk
          # This object emulates Ruby's builtin File::Stat object but uses a virtual file system instead of the real
          # local one. The current implementation is limited to only representing directories and standard files. All
          # attributes are read-only can once the object is created, it is immutable.
          class VirtualStat

            def initialize(**kwargs)
              # directory and file both default to being the opposite of each other, one or both can be specified
              # but they can not both be true at the same time
              is_dir = !!kwargs.fetch(:directory?, !kwargs.fetch(:file?, false)) # defaults to not file which defaults to false
              is_fil = !!kwargs.fetch(:file?, !kwargs.fetch(:directory?, true)) # defaults to not directory which defaults to true
              raise ArgumentError.new('must be either a file or a directory') unless is_dir ^ is_fil

              @values = kwargs.dup
              # the default is a directory
              @values[:directory?] = !@values.delete(:file?) if @values.key?(:file?) # normalize on directory? if file? was specified.

              @birthtime = kwargs[:birthtime] || Time.now
            end

            def blksize
              @values.fetch(:blksize, 4096)
            end

            def blockdev?
              false
            end

            def blocks
              @values.fetch(:blocks, 0)
            end

            def chardev?
              false
            end

            def pipe?
              false
            end

            def socket?
              false
            end

            def symlink?
              false
            end

            def directory?
              @values.fetch(:directory?, true)
            end

            def file?
              !directory?
            end

            def ftype
              raise Errno::ENOENT.new('No such file or directory') unless file? || directory?

              file? ? 'file' : 'directory'
            end

            def size
              @values.fetch(:size, 0)
            end

            def zero?
              file? && size == 0
            end

            def nlink
              @values.fetch(:nlink, 0)
            end

            def dev
              @values[:dev] ||= rand(1..0xfe)
            end

            def ino
              @values[:ino] ||= rand(1..0xfffe)
            end

            def gid
              @values.fetch(:gid, Process.gid)
            end

            def grpowned?
              gid == Process.gid
            end

            def uid
              @values.fetch(:uid, Process.uid)
            end

            def owned?
              uid == Process.uid
            end

            # last access time
            def atime
              @values.fetch(:atime, @birthtime)
            end

            # modification time
            def mtime
              @values.fetch(:mtime, @birthtime)
            end

            # change time
            def ctime
              @values.fetch(:ctime, @birthtime)
            end

            # the permission bits, normalized based on the standard GNU representation,
            # see: https://www.gnu.org/software/libc/manual/html_node/Permission-Bits.html
            def mode
              @values.fetch(:mode, (file? ? 0o644 : 0o755))
            end

            def setuid?
              mode & 0o04000 != 0
            end

            def setgid?
              mode & 0o02000 != 0
            end

            def sticky?
              mode & 0o01000 != 0
            end

            def readable?
              return true if owned? && (mode & 1 << 8 != 0)
              return true if grpowned? && (mode & 1 << 5 != 0)
              return true if world_readable?
              return false
            end

            def world_readable?
              mode & 1 << 2 != 0
            end

            def writable?
              return true if owned? && (mode & 1 << 7 != 0)
              return true if grpowned? && (mode & 1 << 4 != 0)
              return true if world_writable?
              return false
            end

            def world_writable?
              mode & 1 << 1 != 0
            end

            def executable?
              return true if owned? && (mode & 1 << 6 != 0)
              return true if grpowned? && (mode & 1 << 3 != 0)
              return true if mode & 1 != 0
              return false
            end

            attr_reader :birthtime
          end
        end
      end
    end
  end
end
