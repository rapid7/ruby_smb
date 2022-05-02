require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          class Processor < Provider::Processor::Base
            require 'ruby_smb/server/share/provider/disk/processor/close'
            require 'ruby_smb/server/share/provider/disk/processor/create'
            require 'ruby_smb/server/share/provider/disk/processor/query'
            require 'ruby_smb/server/share/provider/disk/processor/read'

            include RubySMB::Server::Share::Provider::Disk::Processor::Close
            include RubySMB::Server::Share::Provider::Disk::Processor::Create
            include RubySMB::Server::Share::Provider::Disk::Processor::Query
            include RubySMB::Server::Share::Provider::Disk::Processor::Read

            Handle = Struct.new(:remote_path, :local_path, :durable?, :file)
            def initialize(provider, server_client, session)
              super
              @handles = {}
              @query_directory_context = {}
            end

            def maximal_access(path=nil)
              RubySMB::SMB2::BitField::FileAccessMask.new(
                read_attr: 1,
                read_data: 1
              )
            end

            private

            def build_fscc_file_attributes(path)
              file_attributes = Fscc::FileAttributes.new
              if path.file?
                file_attributes.normal = 1
              elsif path.directory?
                file_attributes.directory = 1
              end
              file_attributes
            end

            def build_fscc_file_information(path, info_class, rename: nil)
              case info_class
              when Fscc::FileInformation::FILE_EA_INFORMATION
                info = Fscc::FileInformation::FileEaInformation.new
              when Fscc::FileInformation::FILE_FULL_DIRECTORY_INFORMATION
                info = Fscc::FileInformation::FileFullDirectoryInformation.new
                set_common_info(info, path)
                info.file_name = rename || path.basename.to_s
              when Fscc::FileInformation::FILE_ID_BOTH_DIRECTORY_INFORMATION
                info = Fscc::FileInformation::FileIdBothDirectoryInformation.new
                set_common_info(info, path)
                info.file_name = rename || path.basename.to_s
              when Fscc::FileInformation::FILE_NETWORK_OPEN_INFORMATION
                info = Fscc::FileInformation::FileNetworkOpenInformation.new
                set_common_info(info, path)
              when Fscc::FileInformation::FILE_STREAM_INFORMATION
                  unless path.file?
                    raise NotImplementedError, 'Can only generate FILE_STREAM_INFORMATION for files'
                  end

                  info = Fscc::FileInformation::FileStreamInformation.new(
                    stream_size: path.size,
                    stream_allocation_size: get_allocation_size(path),
                    stream_name: '::$DATA'
                  )
              else
                raise NotImplementedError, "Unsupported FSCC file information class: #{info_class} (#{Fscc::FileInformation.name(info_class)})"
              end

              # some have a next offset field that needs to be set accordingly
              if info.respond_to?(:next_offset)
                align = 8
                info.next_offset = info.num_bytes + ((align - info.num_bytes % align) % align)
              end

              info
            end

            def get_allocation_size(path)
              (path.size + (4095 - (path.size + 4095) % 4096))
            end

            def get_local_path(path)
              case path
              # SMB1 uses uint16_t file IDs
              when ::BinData::Uint16le
                local_path = @handles[path]&.local_path
              # SMB2 uses a compound field for file IDs, so convert it to the binary rep and use that as the key
              when Field::Smb2Fileid
                local_path = @handles[path.to_binary_s]&.local_path
              when ::String
                path = path.encode.gsub(/\/|\\/, File::SEPARATOR)
                path = path.delete_prefix(File::SEPARATOR)
                local_path = (provider.path + path.encode).cleanpath
                unless local_path == provider.path || local_path.to_s.start_with?(provider.path.to_s.delete_suffix(File::SEPARATOR) + File::SEPARATOR)
                  raise RuntimeError, "Directory traversal detected to: #{local_path}"
                end
              else
                raise NotImplementedError, "Can not get the local path for: #{path.inspect}, type: #{path.class.inspect}"
              end

              local_path
            end

            # A bunch of structures have these common fields with the same meaning, so set them all here
            def set_common_info(info, path)
              set_common_timestamps(info, path)
              if path.file?
                info.end_of_file = path.size
                info.allocation_size = get_allocation_size(path)
              end
              info.file_attributes = build_fscc_file_attributes(path)
            end

            def set_common_timestamps(info, path)
              begin
                info.create_time = path.birthtime
              rescue NotImplementedError
                logger.warn("The file system does not support #birthtime for #{path}")
              end

              info.last_access = path.atime
              info.last_write = path.mtime
              info.last_change = path.ctime
            end

            # Turn a wildcard expression into a regex. Not all wildcard
            # characters are supported. Wildcards that can not be converted will
            # raise a NotImplementedError.
            #
            # @param [String] wildcard The wildcard expression to convert.
            # @return [Regexp] The converted expression.
            # @raise [NotImplementedError] Raised when the wildcard can not be
            #   converted.
            def wildcard_to_regex(wildcard)
              return Regexp.new('.*') if ['*.*', ''].include?(wildcard)

              if wildcard.each_char.any? { |c| c == '<' || c == '>' }
                # the < > wildcard operators are not supported
                raise NotImplementedError, 'Unsupported wild card characters'
              end

              wildcard = Regexp.escape(wildcard)
              wildcard = wildcard.gsub(/(\\\?)+$/) { |match| ".{0,#{match.length / 2}}"}
              wildcard = wildcard.gsub('\?', '.')
              wildcard = wildcard.gsub('\*', '.*')
              wildcard = wildcard.gsub('"', '\.')
              Regexp.new('^' + wildcard + '$')
            end
          end
        end
      end
    end
  end
end
