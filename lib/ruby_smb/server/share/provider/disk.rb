require 'zlib'
require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          TYPE = TYPE_DISK
          class Processor < Processor::Base
            def initialize(name, path)
              @path = path
              @handle_guids = {}
              super(name)
            end

            def maximal_access(path=nil)
              RubySMB::SMB2::BitField::FileAccessMask.read([0x001f01ff].pack('V'))
            end

            def do_create_smb2(request)
              path = request.name.snapshot.dup
              path = path.encode.gsub('\\', File::SEPARATOR)
              response = RubySMB::SMB2::Packet::CreateResponse.new
              response.create_action = 1
              response.create_time = response.last_access = response.last_write = response.last_change = DateTime.now
              response.file_attributes.directory = 1
              response.file_id.persistent = Zlib::crc32(path)
              response.file_id.volatile = rand(0xffffffff)
              @handle_guids[response.file_id.to_binary_s] = path

              request.contexts.each do |req_ctx|
                case req_ctx.name
                when SMB2::CreateContext::CREATE_QUERY_MAXIMAL_ACCESS
                  res_ctx = SMB2::CreateContext::CreateQueryMaximalAccessResponse.new(
                    maximal_access: maximal_access(path)
                  )
                when SMB2::CreateContext::CREATE_QUERY_ON_DISK_ID
                  res_ctx = SMB2::CreateContext::CreateQueryOnDiskIdResponse.new
                else
                  logger.warn("No handler for context message: #{req_ctx.name}")
                  next
                end

                response.contexts << SMB2::CreateContext::CreateContextResponse.new(name: res_ctx.class::NAME, data: res_ctx)
              end

              if response.contexts.length > 0
                # fixup the offsets
                response.contexts[0...-1].each do |ctx|
                  ctx.next_offset = ctx.num_bytes
                end
                response.contexts[-1].next_offset = 0
                response.contexts_offset = response.buffer.abs_offset
                response.contexts_length = response.buffer.num_bytes
              else
                response.contexts_offset = 0
                response.contexts_length = 0
              end

              response
            end
          end

          attr_accessor :path
        end
      end
    end
  end
end
