module RubySMB
  module Dcerpc
    class Handle

      attr_accessor :pipe
      attr_accessor :last_msg
      attr_accessor :response
      attr_accessor :bind

      def initialize(named_pipe, bind)
        @pipe = named_pipe
        @bind = bind
      end

      def bind(options={})
        ioctl_request(@bind)
      end

      def request(options={})
        ioctl_request(RubySMB::Dcerpc::Request.new(options))
      end

      def ioctl_request(action, options={})
        request = @pipe.set_header_fields(RubySMB::SMB2::Packet::IoctlRequest.new(options))
        request.ctl_code = 0x0011C017
        request.flags.is_fsctl = 0x00000001
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
        if msg.smb2_header.message_id == 6
          dcerpc_response_stub = RubySMB::Dcerpc::Response.read(msg.buffer.to_binary_s).stub
          @response = dcerpc_response_stub.to_binary_s
        end
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
