require 'ruby_smb/server/share/provider/virtual_disk/virtual_pathname'
require 'ruby_smb/server/share/provider/virtual_disk/virtual_stat'

module RubySMB
  class Server
    module Share
      module Provider
        class VirtualDisk < Disk
          class VirtualDynamicFile < VirtualPathname
            def initialize(disk, path, content_size, stat: nil, pad: "\x00")
              stat = stat || VirtualStat.new(file?: true, size: content_size)
              raise ArgumentError.new('stat is not a file') unless stat.file?

              # todo: need to figure something out when the stat.size does not match the content.size

              @content_size = content_size
              @pad = pad
              @generate_content = -> { '' }
              super(disk, path, stat: stat)
            end

            def generate_content(&block)
              if block.nil?
                @generate_content.call
              else
                @generate_content = block
              end
            end

            def open(&block)
              content = generate_content
              if content.length < @content_size
                content = content.ljust(@content_size, @pad)
              elsif content.length > @content_size
                content = content[0...@content_size]
              end

              file = StringIO.new(content)
              block_given? ? block.call(file) : file
            end
          end

          class VirtualStaticFile < VirtualDynamicFile
            def initialize(disk, path, content, stat: nil)
              super(disk, path, content.size)
              generate_content do
                content
              end
            end
          end
        end
      end
    end
  end
end
