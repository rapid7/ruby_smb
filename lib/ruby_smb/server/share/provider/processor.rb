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

            attr_accessor :provider
          end
        end
      end
    end
  end
end
