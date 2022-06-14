module RubySMB
  module SMB2
    # Represents a pipe on the Remote server that we can perform
    # various I/O operations on.
    class Pipe < File
      require 'ruby_smb/dcerpc'

      include RubySMB::Dcerpc

      STATUS_CONNECTED = 0x00000003
      STATUS_CLOSING   = 0x00000004

      def initialize(tree:, response:, name:)
        raise ArgumentError, 'No Name Provided' if name.nil?
        case name
        when 'netlogon', '\\netlogon'
          extend RubySMB::Dcerpc::Netlogon
        when 'srvsvc', '\\srvsvc'
          extend RubySMB::Dcerpc::Srvsvc
        when 'svcctl', '\\svcctl'
          extend RubySMB::Dcerpc::Svcctl
        when 'winreg', '\\winreg'
          extend RubySMB::Dcerpc::Winreg
        when 'samr', '\\samr'
          extend RubySMB::Dcerpc::Samr
        when 'wkssvc', '\\wkssvc'
          extend RubySMB::Dcerpc::Wkssvc
        end
        super(tree: tree, response: response, name: name)
      end

      # Performs a peek operation on the named pipe
      #
      # @param peek_size [Integer] Amount of data to peek
      # @return [RubySMB::SMB2::Packet::IoctlResponse]
      # @raise [RubySMB::Error::InvalidPacket] if not a valid FIoctlResponse response
      # @raise [RubySMB::Error::UnexpectedStatusCode] If status is not STATUS_BUFFER_OVERFLOW or STATUS_SUCCESS
      def peek(peek_size: 0)
        packet = RubySMB::SMB2::Packet::IoctlRequest.new
        packet.ctl_code = RubySMB::Fscc::ControlCodes::FSCTL_PIPE_PEEK
        packet.flags.is_fsctl = true
        # read at least 16 bytes for state, avail, msg_count, first_msg_len
        packet.max_output_response = 16 + peek_size
        packet = set_header_fields(packet)
        raw_response = @tree.client.send_recv(packet)
        response = RubySMB::SMB2::Packet::IoctlResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::IoctlResponse::COMMAND,
            packet:         response
          )
        end

        unless response.status_code == WindowsError::NTStatus::STATUS_BUFFER_OVERFLOW or response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end
        response
      end

      # @return [Integer] The number of bytes available to be read from the pipe
      def peek_available
        packet = peek
        state, avail, msg_count, first_msg_len = packet.buffer.unpack('VVVV')
        # Only 1 of these should be non-zero
        avail or first_msg_len
      end

      # @return [Integer] Pipe status
      def peek_state
        packet = peek
        packet.buffer.unpack('V')[0]
      end

      # @return [Boolean] True if pipe is connected, false otherwise
      def is_connected?
        begin
          state = peek_state
        rescue RubySMB::Error::UnexpectedStatusCode => e
          if e.message == 'STATUS_FILE_CLOSED'
            return false
          end
          raise e
        end
        state == STATUS_CONNECTED
      end

      def dcerpc_request(stub_packet, options={})
        options.merge!(endpoint: stub_packet.class.name.split('::').at(-2))
        dcerpc_request = RubySMB::Dcerpc::Request.new({ opnum: stub_packet.opnum }, options)
        dcerpc_request.stub.read(stub_packet.to_binary_s)
        ioctl_send_recv(dcerpc_request, options)
      end

      def ioctl_send_recv(action, options={})
        request = set_header_fields(RubySMB::SMB2::Packet::IoctlRequest.new(options))
        request.ctl_code = 0x0011C017
        request.flags.is_fsctl = 0x00000001
        # TODO: handle fragmentation when the request size > MAX_XMIT_FRAG
        request.buffer = action.to_binary_s

        ioctl_raw_response = @tree.client.send_recv(request)
        ioctl_response = RubySMB::SMB2::Packet::IoctlResponse.read(ioctl_raw_response)
        unless ioctl_response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::IoctlRequest::COMMAND,
            packet:         ioctl_response
          )
        end
        unless [WindowsError::NTStatus::STATUS_SUCCESS,
                WindowsError::NTStatus::STATUS_BUFFER_OVERFLOW].include?(ioctl_response.status_code)
          raise RubySMB::Error::UnexpectedStatusCode, ioctl_response.status_code
        end

        raw_data = ioctl_response.output_data
        if ioctl_response.status_code == WindowsError::NTStatus::STATUS_BUFFER_OVERFLOW
          raw_data << read(bytes: @tree.client.max_buffer_size - ioctl_response.output_count)
          dcerpc_response = dcerpc_response_from_raw_response(raw_data)
          unless dcerpc_response.pdu_header.pfc_flags.first_frag == 1
            raise RubySMB::Dcerpc::Error::InvalidPacket, "Not the first fragment"
          end
          stub_data = dcerpc_response.stub.to_s

          loop do
            break if dcerpc_response.pdu_header.pfc_flags.last_frag == 1
            raw_data = read(bytes: @tree.client.max_buffer_size)
            dcerpc_response = dcerpc_response_from_raw_response(raw_data)
            stub_data << dcerpc_response.stub.to_s
          end
          stub_data
        else
          dcerpc_response = dcerpc_response_from_raw_response(raw_data)
          dcerpc_response.stub.to_s
        end
      end

      private

      def dcerpc_response_from_raw_response(raw_data)
        dcerpc_response = RubySMB::Dcerpc::Response.read(raw_data)
        if dcerpc_response.pdu_header.ptype == RubySMB::Dcerpc::PTypes::FAULT
          status = dcerpc_response.stub.unpack('V').first
          raise RubySMB::Dcerpc::Error::FaultError.new('A fault occurred', status: status)
        elsif dcerpc_response.pdu_header.ptype != RubySMB::Dcerpc::PTypes::RESPONSE
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Not a Response packet"
        end
        dcerpc_response
      rescue IOError
        raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the DCERPC response"
      end

    end
  end
end
