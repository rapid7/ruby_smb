module RubySMB
  class Server
    class ServerClient
      module TreeConnect
        def do_tree_connect_smb2(request)
          share_name = request.path.encode('UTF-8').split('\\', 4).last
          share_provider = @server.shares[share_name]

          response = RubySMB::SMB2::Packet::TreeConnectResponse.new
          response.smb2_header.credits = 1
          if share_provider.nil?
            logger.warning("Received TREE_CONNECT request for non-existent share: #{share_name}")
            response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_BAD_NETWORK_NAME
            return response
          end
          logger.debug("Received TREE_CONNECT request for share: #{share_name}")

          response.share_type = case share_provider.type
          when :disk
            RubySMB::SMB2::Packet::TreeConnectResponse::SMB2_SHARE_TYPE_DISK
          when :pipe
            RubySMB::SMB2::Packet::TreeConnectResponse::SMB2_SHARE_TYPE_PIPE
          when :print
            RubySMB::SMB2::Packet::TreeConnectResponse::SMB2_SHARE_TYPE_PRINT
          end

          # TODO: set the tree id more intelligently to avoid collisions (maybe reuse too?)
          response.smb2_header.tree_id = tree_id = rand(0xffffffff)
          @tree_connect_table[tree_id] = share_processor = share_provider.new_processor(self)
          response.maximal_access = share_processor.maximal_access

          response
        end

        def do_tree_disconnect_smb2(request)
          share_processor = @tree_connect_table.delete(request.smb2_header.tree_id)
          if share_processor.nil?
            response = SMB2::Packet::ErrorPacket.new
            response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NETWORK_NAME_DELETED
            return response
          end

          logger.debug("Received TREE_DISCONNECT request for share: #{share_processor.provider.name}")
          share_processor.disconnect!
          response = RubySMB::SMB2::Packet::TreeDisconnectResponse.new
          response
        end
      end
    end
  end
end
