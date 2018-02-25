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
      # @return [RubySMB::SMB1::Packet::Trans::PeekNamedPipeResponse]
      def peek(peek_size: 0)
        packet = RubySMB::SMB1::Packet::Trans::PeekNamedPipeRequest.new
        packet.fid = @fid
        packet.parameter_block.max_data_count = peek_size
        packet = @tree.set_header_fields(packet)
        resp = @tree.client.send_recv(packet)
        RubySMB::SMB1::Packet::Trans::PeekNamedPipeResponse.read(resp)
      end

      def peek_available
        packet = peek
        # Only 1 of these should be non-zero
        packet.data_block.trans_parameters.read_data_available or packet.data_block.trans_parameters.message_bytes_length
      end

      def peek_state
        packet = peek
        packet.data_block.trans_parameters.pipe_state
      end

    end
  end
end