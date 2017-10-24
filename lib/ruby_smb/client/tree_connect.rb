module RubySMB
  class Client
    # This module contains all of the methods for a client to connect to a
    # remote share or named pipe.
    module TreeConnect
      #
      # SMB 1 Methods
      #

      # Sends a request to connect to a remote Tree and returns the
      # {RubySMB::SMB1::Tree}
      #
      # @param share [String] the share path to connect to
      # @return [RubySMB::SMB1::Tree] the connected Tree
      def smb1_tree_connect(share)
        request = RubySMB::SMB1::Packet::TreeConnectRequest.new
        request.smb_header.tid = 65_535
        request.data_block.path = share
        raw_response = send_recv(request)
        begin
          response = RubySMB::SMB1::Packet::TreeConnectResponse.read(raw_response)
        rescue EOFError
          response = RubySMB::SMB1::Packet::EmptyPacket.read(raw_response)
        end
        smb1_tree_from_response(share, response)
      end

      # Parses a Tree structure from a Tree Connect Response
      #
      # @param share [String] the share path to connect to
      # @param response [RubySMB::SMB1::Packet::TreeConnectResponse] the response packet to parse into our Tree
      # @return [RubySMB::SMB1::Tree]
      def smb1_tree_from_response(share, response)
        unless response.smb_header.command == RubySMB::SMB1::Commands::SMB_COM_TREE_CONNECT
          raise RubySMB::Error::InvalidPacket, 'Not a TreeConnectResponse'
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end
        RubySMB::SMB1::Tree.new(client: self, share: share, response: response)
      end

      #
      # SMB2 Methods
      #

      # Sends a request to connect to a remote host and returns the Array
      # of shares
      #
      # @return [Array] List of shares
      def smb2_net_share_enum_all(file)
        #cn_num_ctx_items = "\x02\x00\x00\x00"
        #ctx_item_1 = "\x00\x00\x01\x00\xC8O2Kp\x16\xD3\x01\x12xZG\xBFn\xE1\x88\x03\x00\x00\x00\x04]\x88\x8A\xEB\x1C\xC9\x11\x9F\xE8\b\x00+\x10H`\x02\x00\x00\x00"
        #ctx_item_2 = "\x01\x00\x01\x00\xC8O2Kp\x16\xD3\x01\x12xZG\xBFn\xE1\x88\x03\x00\x00\x00,\x1C\xB7l\x12\x98@E\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
        #dce_rpc_bind.p_context_elem = cn_num_ctx_items + ctx_item_1 + ctx_item_2

        p_cont_elem_t_1 = RubySMB::Dcerpc::PContElemT.new
        p_cont_elem_t_2 = RubySMB::Dcerpc::PContElemT.new

        p_cont_elem_t_1.p_cont_id = 0

        # p_cont_elem_t_1.abstract_syntax = RubySMB::Dcerpc::PSyntaxIdT.new(if_uuid: '4b324fc8-1670-01d3-1278-5a47bf6ee188', if_version: 3)
        # p_cont_elem_t_1.transfer_syntaxes = [RubySMB::Dcerpc::PSyntaxIdT.new(if_uuid: '8a885d04-1ceb-11c9-9fe8-08002b104860', if_version: 2)]
        p_cont_elem_t_1.abstract_syntax = RubySMB::Dcerpc::PSyntaxIdT.new
        p_cont_elem_t_1.transfer_syntaxes = [RubySMB::Dcerpc::PSyntaxIdT.new]

        p_cont_elem_t_2.p_cont_id = 1
        # p_cont_elem_t_2.abstract_syntax = RubySMB::Dcerpc::PSyntaxIdT.new(if_uuid: '4b324fc8-1670-01d3-1278-5a47bf6ee188', if_version: 3)
        # p_cont_elem_t_2.transfer_syntaxes = [RubySMB::Dcerpc::PSyntaxIdT.new(if_uuid: '6cb71c2c-9812-4540-0300-000000000000', if_version: 1)]
        p_cont_elem_t_2.abstract_syntax = RubySMB::Dcerpc::PSyntaxIdT.new
        p_cont_elem_t_2.transfer_syntaxes = [RubySMB::Dcerpc::PSyntaxIdT.new]

        dce_rpc_bind = RubySMB::Dcerpc::Bind.new
        dce_rpc_bind.p_context_elem.p_cont_elem = [p_cont_elem_t_1, p_cont_elem_t_2]
        #dce_rpc_bind.p_context_elem.p_cont_elem = [p_cont_elem_t_1]

        file.write(data: dce_rpc_bind.to_binary_s)

        #file.read(bytes: 1024)

        #dce_rpc_query = "050000031000000060000000020000004800000000000f00000002000e000000000000000e0000005c005c00310030002e00370030002e00330033002e003100380000000100000001000000040002000000000000000000ffffffff00000000".strip.gsub(/([A-Fa-f0-9]{1,2})\s*?/) { $1.hex.chr }

        #request = file.set_header_fields(RubySMB::SMB2::Packet::IoctlRequest.new)
        #request.ctl_code = 0x0011C017
        #request.flags.is_fsctl = 0x00000001

        #request.buffer = dce_rpc_query
        #raw_response = send_recv(request)
      end

      # Sends a request to connect to a remote Tree and returns the
      # {RubySMB::SMB2::Tree}
      #
      # @param share [String] the share path to connect to
      # @return [RubySMB::SMB2::Tree] the connected Tree
      def smb2_tree_connect(share)
        request = RubySMB::SMB2::Packet::TreeConnectRequest.new
        request.smb2_header.tree_id = 65_535
        request.encode_path(share)
        raw_response = send_recv(request)
        begin
          response = RubySMB::SMB2::Packet::TreeConnectResponse.read(raw_response)
        rescue EOFError
          response = RubySMB::SMB2::Packet::ErrorPacket.read(raw_response)
        end
        smb2_tree_from_response(share, response)
      end

      # Parses a Tree structure from a Tree Connect Response
      #
      # @param share [String] the share path to connect to
      # @param response [RubySMB::SMB2::Packet::TreeConnectResponse] the response packet to parse into our Tree
      # @return [RubySMB::SMB2::Tree]
      def smb2_tree_from_response(share, response)
        unless response.smb2_header.command == RubySMB::SMB2::Commands::TREE_CONNECT
          raise RubySMB::Error::InvalidPacket, 'Not a TreeConnectResponse'
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code.name
        end
        RubySMB::SMB2::Tree.new(client: self, share: share, response: response)
      end
    end
  end
end
