module RubySMB
  class Server
    class ServerClient
      module IOCTL
        def do_ioctl_smb2(request)
          share_processor = @share_connections[request.smb2_header.tree_id]
          # TODO: need to do something if the tree id is invalid
          share_processor.do_ioctl(request)
        end
      end
    end
  end
end
