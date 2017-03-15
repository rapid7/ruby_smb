module RubySMB
  class Client
    # This module holds all the backend client methods for authentication.
    module Authentication


      #
      # SMB1 Methods
      #

      # Handles the SMB1 NTLMSSP 4-way handshake for Authentication
      def smb1_authenticate
        response = smb1_ntlmssp_negotiate
        challenge_packet = smb1_ntlmssp_challenge_packet(response)
        user_id = challenge_packet.smb_header.uid
        challenge_message = smb1_type2_message(challenge_packet)
        smb1_ntlmssp_authenticate(challenge_message, user_id)
      end

      # Sends the {RubySMB::SMB1::Packet::SessionSetupRequest} packet and
      # receives the response.
      #
      # @return [String] the binary string response from the server
      def smb1_ntlmssp_negotiate
        packet = smb1_ntlmssp_negotiate_packet
        dispatcher.send_packet(packet)
        dispatcher.recv_packet
      end

      # Takes the Base64 encoded NTLM Type 2 (Challenge) message
      # and calls the routines to build the Auth packet, sends the packet
      # and receives the raw response
      #
      # @param type2_string [String] the Base64 Encoded NTLM Type 2 message
      # @return [String] the raw binary response from the server
      def smb1_ntlmssp_authenticate(type2_string,user_id)
        packet = smb1_ntlmssp_auth_packet(type2_string,user_id)
        dispatcher.send_packet(packet)
        dispatcher.recv_packet
      end

      # Generates the {RubySMB::SMB1::Packet::SessionSetupRequest} packet
      # with the NTLM Type 3 (Auth) message in the security_blob field.
      #
      # @param type2_string [String] the Base64 encoded Type2 challenge to respond to
      # @return [RubySMB::SMB1::Packet::SessionSetupRequest] the second authentication packet to send
      def smb1_ntlmssp_auth_packet(type2_string,user_id)
        type3_message = ntlm_client.init_context(type2_string)
        packet = RubySMB::SMB1::Packet::SessionSetupRequest.new
        packet.smb_header.uid = user_id
        packet.set_type3_blob(type3_message.serialize)
        packet.parameter_block.max_buffer_size = 4356
        packet.parameter_block.max_mpx_count = 50
        packet.smb_header.flags2.extended_security = 1
        packet
      end

      # Creates the {RubySMB::SMB1::Packet::SessionSetupRequest} packet
      # for the first part of the NTLMSSP 4-way hnadshake. This packet
      # initializes negotiations for the NTLMSSP authentication
      #
      # @return [RubySMB::SMB1::Packet::SessionSetupRequest] the first authentication packet to send
      def smb1_ntlmssp_negotiate_packet
        type1_message = ntlm_client.init_context
        packet = RubySMB::SMB1::Packet::SessionSetupRequest.new
        packet.set_type1_blob(type1_message.serialize)
        packet.parameter_block.max_buffer_size = 4356
        packet.parameter_block.max_mpx_count = 50
        packet.smb_header.flags2.extended_security = 1
        packet
      end

      # Takes the raw binary string and returns a {RubySMB::SMB1::Packet::SessionSetupResponse}
      def smb1_ntlmssp_challenge_packet(raw_response)
        packet = RubySMB::SMB1::Packet::SessionSetupResponse.read(raw_response)
        status_code = WindowsError::NTStatus.find_by_retval(packet.smb_header.nt_status.value).first

        unless status_code.name == "STATUS_MORE_PROCESSING_REQUIRED"
          raise RubySMB::Error::UnexpectedStatusCode, status_code.to_s
        end

        unless packet.smb_header.command == RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP
          raise RubySMB::Error::InvalidPacket, "Command was #{packet.smb_header.command} and not #{RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP}"
        end
        packet
      end

      # Parses out the NTLM Type 2 Message from a {RubySMB::SMB1::Packet::SessionSetupResponse}
      #
      # @param response_packet [RubySMB::SMB1::Packet::SessionSetupResponse] the response packet to get the NTLM challenge from
      # @return [String] the base64 encoded  NTLM Challenge (Type2 Message) from the response
      def smb1_type2_message(response_packet)
        sec_blob = response_packet.data_block.security_blob
        ntlmssp_offset = sec_blob.index("NTLMSSP")
        type2_blob = sec_blob.slice(ntlmssp_offset..-1)
        [type2_blob].pack("m")
      end
    end
  end
end