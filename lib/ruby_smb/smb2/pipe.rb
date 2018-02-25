module RubySMB
  module SMB2
    # Represents a pipe on the Remote server that we can perform
    # various I/O operations on.
    class Pipe < File

      STATUS_CONNECTED = 0x00000003
      STATUS_CLOSING   = 0x00000004

      # Performs a peek operation on the named pipe
      #
      # @param peek_size [Integer] Amount of data to peek
      # @return [RubySMB::SMB2::Packet::IoctlResponse]
      def peek(peek_size: 0)
        packet = RubySMB::SMB2::Packet::IoctlRequest.new
        packet.ctl_code = RubySMB::Fscc::ControlCodes::FSCTL_PIPE_PEEK
        packet.flags.is_fsctl = true
        # read at least 16 bytes for state, avail, msg_count, first_msg_len
        packet.max_output_response = 16 + peek_size
        packet = set_header_fields(packet)
        resp = @tree.client.send_recv(packet)
        RubySMB::SMB2::Packet::IoctlResponse.read(resp)
      end

      def peek_available
        packet = peek
        state, avail, msg_count, first_msg_len = packet.buffer.unpack('VVVV')
        # Only 1 of these should be non-zero
        avail or first_msg_len
      end

      def peek_state
        packet = peek
        packet.buffer.unpack('V')[0]
      end

    end
  end
end