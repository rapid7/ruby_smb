module RubySMB
  module Dcerpc
    class Handle

      attr_accessor :pipe
      attr_accessor :last_msg

      def initialize(named_pipe)
        @pipe = named_pipe
      end

      def bind(options={})
        ioctl_request(RubySMB::Dcerpc::Bind.new(options))
      end

      def request(options={})
        ioctl_request(RubySMB::Dcerpc::Request.new(options))
      end

      def ioctl_request(action, options={})
        request = @pipe.set_header_fields(RubySMB::SMB2::Packet::IoctlRequest.new(options))
        request.ctl_code = 0x0011C017
        request.flags.is_fsctl =  0x00000001
        request.buffer = action.to_binary_s
        @last_msg = @pipe.tree.client.send_recv(request)
        handle_msg(RubySMB::SMB2::Packet::IoctlResponse.read(@last_msg))
      end

      def wait_listen
        @last_msg = @pipe.tree.client.dispatcher
                        .tcp_socket.recvmsg.first
        handle_msg(RubySMB::SMB2::Packet::IoctlResponse.read(@last_msg))
      end

      def handle_msg(msg)
        case msg.status_code
          when WindowsError::NTStatus::STATUS_PENDING
            wait_listen
          else
            handle_dcerpc(msg)
        end
      end

      def handle_dcerpc(msg)
        case msg.class
          when RubySMB::SMB2::Packet::ErrorPacket
            msg
          when RubySMB::SMB2::Packet::IoctlResponse
            msg
        end
      end

    end
  end
end
