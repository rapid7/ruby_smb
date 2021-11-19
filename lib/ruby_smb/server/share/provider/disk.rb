require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          TYPE = TYPE_DISK
          class Processor < Processor::Base
            def maximal_access
              RubySMB::SMB2::BitField::DirectoryAccessMask.read([0x001f01ff].pack('V'))
            end
          end

          def initialize(name, path)
            @path = path
            super(name)
          end

          attr_accessor :path
        end
      end
    end
  end
end
