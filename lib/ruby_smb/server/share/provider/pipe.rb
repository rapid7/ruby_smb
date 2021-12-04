require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Pipe < Base
          TYPE = TYPE_PIPE
        end

        class IpcPipe < Pipe
          class Processor < Processor::Base
            def maximal_access(path=nil)
              RubySMB::SMB2::BitField::DirectoryAccessMask.read([0x001f00a9].pack('V'))
            end
          end

          def initialize(name='IPC$')
            super
          end
        end
      end
    end
  end
end
