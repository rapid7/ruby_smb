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

        #file

        #request = file.set_header_fields(RubySMB::SMB2::Packet::IoctlRequest.new)
        ##request.smb2_header.tree_id = 0x00000001
        #request.ctl_code = 0x0011C017
        #request.flags.is_fsctl = 0x00000001
        #request.file_id = file.guid

        #request.buffer = "05000b03100000007400000002000000b810b810000000000200000000000100c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe808002b1048600200000001000100c84f324b7016d30112785a47bf6ee188030000002c1cb76c12984045030000000000000001000000".strip.gsub(/([A-Fa-f0-9]{1,2})\s*?/) { $1.hex.chr }
        #raw_response = send_recv(request)
        #begin
        #  response = RubySMB::SMB2::Packet::IoctlResponse.read(raw_response)
        #rescue EOFError
        #  response = RubySMB::SMB2::Packet::ErrorPacket.read(raw_response)
        #end

        dce_rpc_query = "05000b03100000007400000002000000b810b810000000000200000000000100c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe808002b1048600200000001000100c84f324b7016d30112785a47bf6ee188030000002c1cb76c12984045030000000000000001000000".strip.gsub(/([A-Fa-f0-9]{1,2})\s*?/) { $1.hex.chr }
        file.write(data: dce_rpc_query)
        file.read(bytes: 1024)
        dce_rpc_query = "050000031000000060000000020000004800000000000f00000002000e000000000000000e0000005c005c00310030002e00370030002e00330033002e003100380000000100000001000000040002000000000000000000ffffffff00000000".strip.gsub(/([A-Fa-f0-9]{1,2})\s*?/) { $1.hex.chr }

        request = file.set_header_fields(RubySMB::SMB2::Packet::IoctlRequest.new)
        request.ctl_code = 0x0011C017
        request.flags.is_fsctl = 0x00000001

        request.buffer = dce_rpc_query
        raw_response = send_recv(request)
        begin
          response = RubySMB::SMB2::Packet::IoctlResponse.read(raw_response)
        rescue EOFError
          response = RubySMB::SMB2::Packet::ErrorPacket.read(raw_response)
        end

        #transact_nmpipe_request.data_block.trans_data.write_data = dce_rpc_query
        #resp = client.send_recv(transact_nmpipe_request)
        #transact_nmpipe_response = RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse.new
        #transact_nmpipe_response.read(resp)
        #puts transact_nmpipe_response.data_block.trans_data.read_data
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
