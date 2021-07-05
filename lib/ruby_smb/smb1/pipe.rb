module RubySMB
  module SMB1
    # Represents a pipe on the Remote server that we can perform
    # various I/O operations on.
    class Pipe < File
      require 'ruby_smb/dcerpc'

      include RubySMB::Dcerpc

      # Reference: https://msdn.microsoft.com/en-us/library/ee441883.aspx
      STATUS_DISCONNECTED = 0x0001
      STATUS_LISTENING    = 0x0002
      STATUS_OK           = 0x0003
      STATUS_CLOSED       = 0x0004

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
        end
        super(tree: tree, response: response, name: name)
      end

      # Performs a peek operation on the named pipe
      #
      # @param peek_size [Integer] Amount of data to peek
      # @return [RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse]
      # @raise [RubySMB::Error::InvalidPacket] If not a valid PeekNmpipeResponse
      # @raise [RubySMB::Error::UnexpectedStatusCode] If status is not STATUS_BUFFER_OVERFLOW or STATUS_SUCCESS
      def peek(peek_size: 0)
        packet = RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest.new
        packet.fid = @fid
        packet.parameter_block.max_data_count = peek_size
        packet = @tree.set_header_fields(packet)
        raw_response = @tree.client.send_recv(packet)
        response = RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest::COMMAND,
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
        # Only 1 of these should be non-zero
        packet.data_block.trans_parameters.read_data_available or packet.data_block.trans_parameters.message_bytes_length
      end

      # @return [Integer] Pipe status
      def peek_state
        packet = peek
        packet.data_block.trans_parameters.pipe_state
      end

      # @return [Boolean] True if pipe is connected, false otherwise
      def is_connected?
        begin
          state = peek_state
        rescue RubySMB::Error::UnexpectedStatusCode => e
          if e.message == 'STATUS_INVALID_HANDLE'
            return false
          end
          raise e
        end
        state == STATUS_OK
      end

      # Send a DCERPC request with the provided stub packet.
      #
      # @params stub_packet [#opnum] the stub packet to add to the DCERPC request
      # @return [String] the raw DCERPC response stub
      # @raise [RubySMB::Error::InvalidPacket] if the response is not valid
      # @raise [RubySMB::Error::UnexpectedStatusCode] if the response status code is different than STATUS_SUCCESS or STATUS_BUFFER_OVERFLOW
      def dcerpc_request(stub_packet, options={})
        options.merge!(endpoint: stub_packet.class.name.split('::').at(-2))
        dcerpc_request = RubySMB::Dcerpc::Request.new({ opnum: stub_packet.opnum }, options)
        dcerpc_request.stub.read(stub_packet.to_binary_s)
        trans_nmpipe_request = RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest.new(options)
        @tree.set_header_fields(trans_nmpipe_request)
        trans_nmpipe_request.set_fid(@fid)
        trans_nmpipe_request.data_block.trans_data.write_data = dcerpc_request.to_binary_s

        trans_nmpipe_raw_response = @tree.client.send_recv(trans_nmpipe_request)
        trans_nmpipe_response = RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse.read(trans_nmpipe_raw_response)
        unless trans_nmpipe_response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse::COMMAND,
            packet:         trans_nmpipe_response
          )
        end
        unless [WindowsError::NTStatus::STATUS_SUCCESS,
                WindowsError::NTStatus::STATUS_BUFFER_OVERFLOW].include?(trans_nmpipe_response.status_code)
          raise RubySMB::Error::UnexpectedStatusCode, trans_nmpipe_response.status_code
        end

        raw_data = trans_nmpipe_response.data_block.trans_data.read_data.to_binary_s
        if trans_nmpipe_response.status_code == WindowsError::NTStatus::STATUS_BUFFER_OVERFLOW
          raw_data << read(bytes: @tree.client.max_buffer_size - trans_nmpipe_response.parameter_block.data_count)
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
        unless dcerpc_response.pdu_header.ptype == RubySMB::Dcerpc::PTypes::RESPONSE
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Not a Response packet"
        end
        dcerpc_response
      rescue IOError
        raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the DCERPC response"
      end

    end
  end
end
