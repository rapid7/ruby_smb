module RubySMB
  class Server
    class ServerClient
      module ShareIO
        def do_create_smb2(request)
          share_processor = @share_connections[request.smb2_header.tree_id]
          # TODO: need to do something if the tree id is invalid
          name = request.name.read_now!
          logger.debug("Received Create request for: #{share_processor.provider.name}\\#{name}")
          share_processor.do_create_smb2(request)
        end

        def do_ioctl_smb2(request)
          share_processor = @share_connections[request.smb2_header.tree_id]
          # TODO: need to do something if the tree id is invalid
          logger.debug("Received IOCTL request for share: #{share_processor.provider.name}")
          share_processor.do_ioctl_smb2(request)
        end

        def do_query_directory_smb2(request)
          share_processor = @share_connections[request.smb2_header.tree_id]
          # TODO: need to do something if the tree id is invalid
          logger.debug("Received Query Directory request for share: #{share_processor.provider.name}")
          share_processor.do_query_directory_smb2(request)
        end
      end
    end
  end
end
