module RubySMB
  class Server
    class ServerClient
      class Share
        TYPE_DISK = :disk
        TYPE_PIPE = :pipe
        TYPE_PRINT = :print

        # A provider is unique to a particular share
        class BaseProvider
          # A processor is unique to a particular client connection
          class BaseProcessor
            def initialize(provider, server_client)
              @provider = provider
              @server_client = server_client
            end

            def maximal_access
              RubySMB::SMB2::BitField::DirectoryAccessMask.new
            end

            def do_ioctl(request)
              response = RubySMB::SMB2::Packet::IoctlResponse.new
              response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NOT_FOUND.value
              response.smb2_header.credits = 1
              response
            end

            def server
              @server_client.server
            end
          end

          def new_processor(server_client)
            self.class::Processor.new(self, server_client)
          end

          def type
            self.class::TYPE
          end
        end

        class DiskProvider < BaseProvider
          TYPE = TYPE_DISK
          class Processor < BaseProvider::BaseProcessor
          end

          def initialize(path)
            @path = path
          end

          attr_accessor :path
        end

        class PipeProvider < BaseProvider
          TYPE = TYPE_PIPE
        end

        class IpcPipeProvider < PipeProvider
          class Processor < BaseProvider::BaseProcessor
            def maximal_access
              RubySMB::SMB2::BitField::DirectoryAccessMask.read([0x001f00a9].pack('V'))
            end
          end
        end

        class PrintProvider < BaseProvider
          TYPE = TYPE_PRINT
        end
      end

      module Shares
        def do_ioctl_smb2(packet)
          share_processor = @share_connections[packet.smb2_header.tree_id]
          # TODO: need to do something if the tree id is invalid
          share_processor.do_ioctl(packet)
        end

        # TODO: need to handle tree-disconnect requests
        def do_tree_connect_smb2(packet)
          path = packet.path.encode('UTF-8').split('\\', 4).last
          share_provider = @shares[path]

          response = RubySMB::SMB2::Packet::TreeConnectResponse.new
          response.smb2_header.credits = 1
          if share_provider.nil?
            response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_BAD_NETWORK_NAME.value
            return response
          end

          response.share_type = case share_provider.type
          when :disk
            RubySMB::SMB2::Packet::TreeConnectResponse::SMB2_SHARE_TYPE_DISK
          when :pipe
            RubySMB::SMB2::Packet::TreeConnectResponse::SMB2_SHARE_TYPE_PIPE
          when :print
            RubySMB::SMB2::Packet::TreeConnectResponse::SMB2_SHARE_TYPE_PRINT
          end

          response.smb2_header.tree_id = tree_id = rand(0xffffffff)
          @share_connections[tree_id] = share_processor = share_provider.new_processor(self)
          response.maximal_access = share_processor.maximal_access

          response
        end
      end
    end
  end
end
