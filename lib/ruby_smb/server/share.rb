module RubySMB
  class Server
    module Share
      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96
      TYPE_DISK = 1
      TYPE_PIPE = 2
      TYPE_PRINT = 3

      class Base
        attr_accessor :comment, :name

        def type
          self.class::TYPE
        end
      end

      class Disk < Base
        TYPE = TYPE_DISK

        def initialize(name)
          @name = name
        end
      end
    end
  end
end
