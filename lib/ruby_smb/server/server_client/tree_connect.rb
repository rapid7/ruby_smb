module RubySMB
  class Server
    class ServerClient
      module TreeConnect
        def do_tree_connect_smb2(request)
          share_name = request.path.value.encode.split('\\')[3]

          share = @server.shares.find { |s| s.name == share_name }
          if share.nil?
            return SMB2::SMB2Header.new(nt_status: WindowsError::NTStatus::STATUS_BAD_NETWORK_NAME.value)
          end

          tree_id = rand(0x100000000)
          @tree_connections[tree_id] = share

          response = SMB2::Packet::TreeConnectResponse.new
          response.smb2_header.credits = 1
          response.smb2_header.tree_id = tree_id
          response.share_type = share.type
          response.maximal_access.list = 1
          response.maximal_access.read_ea = 1
          response.maximal_access.traverse = 1
          response.maximal_access.read_attr = 1
          response.maximal_access.delete_access = 1
          response.maximal_access.read_control = 1
          response.maximal_access.write_dac = 1
          response.maximal_access.write_owner = 1
          response.maximal_access.synchronize = 1
          response
        end
      end
    end
  end
end
