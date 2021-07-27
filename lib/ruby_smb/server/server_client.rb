module RubySMB
  class Server
    class ServerClient
      def initialize(dispatcher)
        @dispatcher = dispatcher
        @state = :negotiating
      end

      def run
        loop do
          raw_data = recv_packet

          case @state
          when :negotiating
            handle_negotiation(raw_data)
          end

          break if @dispatcher.tcp_socket.closed?
        end
      end

      def disconnect!
        @dispatcher.tcp_socket.close
      end

      private

      def recv_packet
        @dispatcher.recv_packet
      end

      def send_packet(packet)
        @dispatcher.send_packet(packet)
      end

      def handle_negotiation(packet)
        case packet[0...4]
        when "\xff\x53\x4d\x42".b
          handle_negotiation_smb1(packet)
          #when "\xfe\x53\x4d\x42".b
          #  handle_negotiation_smb2(packet)
        else
          disconnect!
        end
      end

      def handle_negotiation_smb1(packet)
        # SMB1 is not supported yet
        response = RubySMB::SMB1::Packet::NegotiateResponse.new
        response.parameter_block.word_count = 1
        response.parameter_block.dialect_index = 0xffff
        response.data_block.byte_count = 0
        send_packet(response)
        disconnect!
      end
    end
  end
end
