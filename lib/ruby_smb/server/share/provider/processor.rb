module RubySMB
  class Server
    module Share
      module Provider
        module Processor
          # A processor is unique to a particular client connection-session
          # combination and provides the share's functionality.
          class Base
            def initialize(provider, server_client, session)
              @provider = provider
              @server_client = server_client
              @session = session
            end

            # Get the maximum access that can be obtained for the specified
            # path. If no path is specified, the maximum access for the share as
            # a whole is returned.
            #
            # @param [Pathname] path
            # @return [RubySMB::SMB2::BitField::FileAccessMask]
            def maximal_access(path=nil)
              RubySMB::SMB2::BitField::FileAccessMask.new
            end

            def disconnect!
            end

            def do_close_smb1(request)
              raise NotImplementedError
            end

            def do_nt_create_andx_smb1(request)
              raise NotImplementedError
            end

            def do_read_andx_smb1(request)
              raise NotImplementedError
            end

            def do_transactions2_smb1(request)
              raise NotImplementedError
            end

            def do_close_smb2(request)
              raise NotImplementedError
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

            def do_query_info_smb2(request)
              raise NotImplementedError
            end

            def do_read_smb2(request)
              raise NotImplementedError
            end

            #
            # The logger object associated with this instance.
            #
            # @return [Logger]
            def logger
              @server_client.logger
            end

            def server
              @server_client.server
            end

            # Forward a share IO method for a particular request. This is a choke point to allow any hooks that were
            # registered with the share provider to be executed before and after the specified method is invoked to
            # process the request and generate the response. This is used for both SMB1 and SMB2 requests.
            #
            # @param [Symbol] method_name The method name to forward the request to
            # @param [RubySMB::GenericPacket] request The request packet to be processed
            # @return [RubySMB::GenericPacket]
            def share_io(method_name, request)
              @provider.hooks.each do |hook|
                next unless hook.request_class == request.class && hook.location == :before

                request = hook.callback.call(@session, request) || request
              end

              response = send(method_name, request)

              @provider.hooks.each do |hook|
                next unless hook.request_class == request.class && hook.location == :after

                response = hook.callback.call(@session, request, response) || response
              end

              response
            end

            # The underlying share provider that this is a processor for.
            # @!attribute [r] provider
            #   @return [RubySMB::Server::Share::Provider::Base]
            attr_accessor :provider
          end
        end
      end
    end
  end
end
