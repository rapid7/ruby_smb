module RubySMB
  module SMB1
    # Represents a pipe on the Remote server that we can perform
    # various I/O operations on.
    class Pipe < File

      # Reference: https://msdn.microsoft.com/en-us/library/ee441883.aspx
      STATUS_DISCONNECTED = 0x0001
      STATUS_LISTENING    = 0x0002
      STATUS_OK           = 0x0003
      STATUS_CLOSED       = 0x0004

      # Performs a peek operation on the named pipe
      #
      # @param peek_size [Integer] Amount of data to peek
      # @return [RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse]
      # @raise [RubySMB::Error::InvalidPacket] if not a valid PeekNmpipeResponse
      def peek(peek_size: 0)
        packet = RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest.new
        packet.fid = @fid
        packet.parameter_block.max_data_count = peek_size
        packet = @tree.set_header_fields(packet)
        raw_response = @tree.client.send_recv(packet)
        response = RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse.read(raw_response)

        unless response.smb_header.command == RubySMB::SMB1::Commands::SMB_COM_TRANSACTION
          raise RubySMB::Error::InvalidPacket, 'Not a TransResponse packet'
        end
        response
      end

      # @return [Integer] The number of bytes available to be read from the pipe
      def peek_available
        packet = peek
        # Only 1 of these should be non-zero
        packet.data_block.trans_parameters.read_data_available or packet.data_block.trans_parameters.message_bytes_length
      end

      # @return [Integer] Pipe status
      def peek_state
        packet = peek
        packet.data_block.trans_parameters.pipe_state
      end

    end
  end
end
