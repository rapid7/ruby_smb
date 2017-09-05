module RubySMB
  module Dispatcher
    # Provides the base class for the packet dispatcher.
    class Base
      # @param packet [#length]
      # @return [Fixnum] NBSS header to go in front of `packet`
      def nbss(packet)
        [packet.do_num_bytes].pack('N')
      end

      # @abstract
      def send_packet(_packet)
        raise NotImplementedError
      end

      # @abstract
      def recv_packet
        raise NotImplementedError
      end
    end
  end
end
