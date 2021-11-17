module RubySMB
  class Server
    module Share
      module Provider
        class Base
          def initialize(name)
            @name = name
          end

          def new_processor(server_client)
            self.class::Processor.new(self, server_client)
          end

          def type
            self.class::TYPE
          end

          attr_accessor :name
        end
      end
    end
  end
end

require 'ruby_smb/server/share/provider/disk'
require 'ruby_smb/server/share/provider/pipe'
