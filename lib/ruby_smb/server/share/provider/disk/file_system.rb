module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          module FileSystem
            # define attributes of the file system to emulate
            FileSystem = Struct.new(
              :name,
              :max_name_bytes,
              :case_sensitive_search,
              :case_preserved_names,
              :unicode_on_disk
            )

            NTFS = FileSystem.new(
              'NTFS',
              255,
              true,
              true,
              true
            )
          end
        end
      end
    end
  end
end
