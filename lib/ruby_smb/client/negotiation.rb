module RubySMB
  class Client
    # This module holds all of the methods backing the {RubySMB::Client#negotiate} method
    module Negotiation

      # Creates and dispatches the first Negotiate Request Packet and
      # returns the raw response data.
      #
      # @return [String] the raw binary string containing the response from the server
      def negotiate_request
        if smb1
          request = smb1_negotiate_request
        elsif smb2
          request = smb2_negotiate_request
        end
        dispatcher.send_packet request
        raw_response = dispatcher.recv_packet
      end

      # Takes the raw response data from the server and tries
      # parse it into a valid Response packet object.
      # This method currently assumes that all SMB1 will use Extended Security.
      #
      # @param raw_data [String] the raw binary response from the server
      # @return [RubySMB::SMB1::Packet::NegotiateResponseExtended] when the response is an SMB1 Extended Security Negotiate Response Packet
      # @return [RubySMB::SMB2::Packet::NegotiateResponse] when the response is an SMB2 Negotiate Response Packet
      def negotiate_response(raw_data)
        response = nil
        if smb1
          begin
            packet = RubySMB::SMB1::Packet::NegotiateResponseExtended.read raw_data
          rescue Exception => e
            raise RubySMB::Error::InvalidPacket, "Not a Valid SMB1 Negoitate Response #{e.message}"
          end
          if packet.valid?
            response = packet
          end
        end
        if smb2 && response.nil?
          begin
            packet = RubySMB::SMB2::Packet::NegotiateResponse.read raw_data
          rescue Exception => e
            raise RubySMB::Error::InvalidPacket, "Not a Valid SMB2 Negoitate Response #{e.message}"
          end
          response = packet
        end
        if response.nil?
          raise RubySMB::Error::InvalidPacket, "No Valid Negotiate Response found"
        end
        response
      end

      # Sets the supported SMB Protocol and whether or not
      # Signing is enabled based on the Negotiate Response Packet.
      #
      # @param packet [RubySMB::SMB1::Packet::NegotiateResponseExtended] if SMB1 was negotiated
      # @param packet [RubySMB::SMB2::Packet::NegotiateResponse] if SMB2 was negotiated
      # @return [void] This method sets state and does not return a meaningful value
      def parse_negotiate_response(packet)
        case packet
          when RubySMB::SMB1::Packet::NegotiateResponseExtended
            self.smb1 = true
            self.smb2 = false
            if packet.parameter_block.security_mode.security_signatures_required == 1
              self.signing_required = true
            else
              self.signing_required = false
            end
            'SMB1'
          when RubySMB::SMB2::Packet::NegotiateResponse
            self.smb1 = false
            self.smb2 = true
            if packet.security_mode.signing_required == 1
              self.signing_required = true
            else
              self.signing_required = false
            end
            'SMB2'
        end
      end


      # Create a {RubySMB::SMB1::Packet::NegotiateRequest} packet with the
      # dialects filled in based on the protocol options set on the Client.
      #
      # @return [RubySMB::SMB1::Packet::NegotiateRequest] a completed SMB1 Negotiate Request packet
      def smb1_negotiate_request
        packet = RubySMB::SMB1::Packet::NegotiateRequest.new
        # Default to always enabling Extended Security. It simplifies the Negotiation process
        # while being gauranteed to work with any modern Windows system. We can get more sophisticated
        # with switching this on and off at a later date if the need arises.
        packet.smb_header.flags2.extended_security = 1
        # There is no real good reason to ever send an SMB1 Negotiate packet
        # to Negotiate strictly SMB2, but the protocol WILL support it
        packet.add_dialect(SMB1_DIALECT_SMB1_DEFAULT) if smb1
        packet.add_dialect(SMB1_DIALECT_SMB2_DEFAULT) if smb2
        packet
      end

      # Create a {RubySMB::SMB2::Packet::NegotiateRequest} packet with
      # the default dialect added. This will never be used when we
      # may want to communicate over SMB1
      #
      # @ return [RubySMB::SMB2::Packet::NegotiateRequest] a completed SMB2 Negotiate Request packet
      def smb2_negotiate_request
        packet = RubySMB::SMB2::Packet::NegotiateRequest.new
        packet.smb2_header.message_id = self.smb2_message_id
        # Increment the message id when doing SMB2
        self.smb2_message_id += 1
        packet.security_mode.signing_enabled = 1
        packet.add_dialect(SMB2_DIALECT_DEFAULT)
        packet
      end
    end
  end
end