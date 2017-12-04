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
        # require 'pry'
        # binding.pry
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

      def self.parse_response(response)

        shares = []

        res = response.dup
        win_error = res.slice!(-4, 4).unpack("V")[0]

        if win_error != 0
          raise RuntimeError, "Invalid DCERPC response: win_error = #{win_error}"
        end

        # Remove unused data
        res.slice!(0,12) # level, CTR header, Reference ID of CTR
        share_count = res.slice!(0, 4).unpack("V")[0]
        res.slice!(0,4) # Reference ID of CTR1
        share_max_count = res.slice!(0, 4).unpack("V")[0]

        if share_max_count != share_count
          raise RuntimeError, "Invalid DCERPC response: count != count max (#{share_count}/#{share_max_count})"
        end

        # ReferenceID / Type / ReferenceID of Comment
        types = res.slice!(0, share_count * 12).scan(/.{12}/n).map{|a| a[4,2].unpack("v")[0]}

        share_count.times do |t|
          length, offset, max_length = res.slice!(0, 12).unpack("VVV")
          if offset != 0
            raise RuntimeError, "Invalid DCERPC response: offset != 0 (#{offset})"
          end

          if length != max_length
            raise RuntimeError, "Invalid DCERPC response: length !=max_length (#{length}/#{max_length})"
          end
          name = res.slice!(0, 2 * length).gsub('\x00','')
          res.slice!(0,2) if length % 2 == 1 # pad

          comment_length, comment_offset, comment_max_length = res.slice!(0, 12).unpack("VVV")

          if comment_offset != 0
            raise RuntimeError, "Invalid DCERPC response: comment_offset != 0 (#{comment_offset})"
          end

          if comment_length != comment_max_length
            raise RuntimeError, "Invalid DCERPC response: comment_length != comment_max_length (#{comment_length}/#{comment_max_length})"
          end

          comment = res.slice!(0, 2 * comment_length)

          res.slice!(0,2) if comment_length % 2 == 1 # pad

          name    = name.gsub("\x00", "")
          s_type  = [ 'DISK', 'PRINTER', 'DEVICE', 'IPC', 'SPECIAL', 'TEMPORARY' ][types[t]].gsub("\x00", "")
          comment = comment.gsub("\x00", "")

          shares << [ name, s_type, comment ]
        end

        shares
      end

    end
  end
end
