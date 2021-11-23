module RubySMB
  class Server
    module Share
      module Provider
        module Processor
          # A processor is unique to a particular client connection
          class Base
            def initialize(provider, server_client)
              @provider = provider
              @server_client = server_client
            end

            def maximal_access(path=nil)
              RubySMB::SMB2::BitField::FileAccessMask.new
            end

            def disconnect!
            end

            def do_create_smb2(request)
              raise NotImplementedError
            end

            def do_ioctl_smb2(request)
              response = RubySMB::SMB2::Packet::IoctlResponse.new
              response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NOT_FOUND
              response.smb2_header.credits = 1
              response
            end

            def do_query_directory_smb2(request)
              raise NotImplementedError
            end

            def logger
              @server_client.logger
            end

            def server
              @server_client.server
            end

            attr_accessor :provider
          end
        end
      end
    end
  end
end
