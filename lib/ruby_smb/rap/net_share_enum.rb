module RubySMB
  module Rap
    # NetShareEnum (RAP opcode 0), as defined in [MS-RAP 3.3.4.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rap/48dd86d2-4092-49a4-9024-308f0ed77520).
    # Carried over `\PIPE\LANMAN` using SMB_COM_TRANSACTION. Request parameters
    # describe the shape of the data the server returns; response parameters
    # carry the RAP status, entry count, and buffer sizing hint, and the
    # response data block is an array of `share_info_1` records.
    module NetShareEnum
      OPCODE = 0

      # Parameter descriptor for the RAP call itself: (W)ord info level,
      # (r)eturn buffer pointer, (L)ength hint, (e)ntry count, (h)andle.
      PARAM_DESCRIPTOR = 'WrLeh'.freeze

      # Data descriptor for `share_info_1`: (B)13 name, (B)yte pad, (W)ord type,
      # (z) pointer to remark. See MS-RAP 3.2.4 for descriptor syntax.
      DATA_DESCRIPTOR_LEVEL_1 = 'B13BWz'.freeze

      # Default server receive-buffer size.
      DEFAULT_RECEIVE_BUFFER_SIZE = 0x1000

      # Single share entry (`share_info_1`) as it appears on the wire.
      # MS-RAP 2.5.21. Fixed 20-byte layout.
      class ShareInfo1 < BinData::Record
        endian :little

        string :netname,        length: 13, trim_padding: true
        uint8  :pad1
        uint16 :share_type
        uint32 :remark_offset
      end

      # Parameters block of the RAP request (sent in SMB trans_parameters).
      # Variable-length because of the null-terminated descriptor strings.
      class Request < BinData::Record
        endian :little

        uint16   :opcode,              asserted_value: OPCODE
        stringz  :param_descriptor,    initial_value: PARAM_DESCRIPTOR
        stringz  :data_descriptor,     initial_value: DATA_DESCRIPTOR_LEVEL_1
        uint16   :info_level,          initial_value: 1
        uint16   :receive_buffer_size, initial_value: DEFAULT_RECEIVE_BUFFER_SIZE
      end

      # Parameters block of the RAP response.
      # MS-RAP 3.3.5.1 NetShareEnum Response.
      class Response < BinData::Record
        endian :little

        uint16 :status
        uint16 :converter
        uint16 :entry_count
        uint16 :available
      end

      # Sends a RAP NetShareEnum over `\PIPE\LANMAN` using the tree's
      # existing SMB1 connection. Does not rely on having an opened pipe FID
      # because Win9x does not permit OPEN_ANDX on `\PIPE\LANMAN`; RAP trans
      # is accepted directly against the IPC$ tree.
      #
      # @return [Array<Hash>] each entry has :name (String) and :type (Integer).
      # @raise [RubySMB::Error::InvalidPacket] on a malformed SMB response.
      # @raise [RubySMB::Error::UnexpectedStatusCode] on a non-success SMB status.
      # @raise [RubySMB::Error::RubySMBError] on a non-zero RAP status.
      def net_share_enum
        request = build_net_share_enum_request
        raw_response = tree.client.send_recv(request)
        response = RubySMB::SMB1::Packet::Trans::Response.read(raw_response)
        validate_trans_response!(response)
        parse_net_share_enum_response(response)
      end

      private

      def build_net_share_enum_request
        request = RubySMB::SMB1::Packet::Trans::Request.new
        request.smb_header.tid           = tree.id
        request.smb_header.flags2.unicode = 0
        request.data_block.name          = "\\PIPE\\LANMAN\x00".b
        request.data_block.trans_parameters = Request.new.to_binary_s
        request.parameter_block.max_parameter_count = 8
        request.parameter_block.max_data_count      = DEFAULT_RECEIVE_BUFFER_SIZE
        request
      end

      def validate_trans_response!(response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::Trans::Response::COMMAND,
            packet:         response
          )
        end
        unless response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, response.status_code
        end
      end

      def parse_net_share_enum_response(response)
        params_bytes = response.data_block.trans_parameters.to_s
        if params_bytes.bytesize < Response.new.num_bytes
          raise RubySMB::Error::InvalidPacket, 'Truncated RAP NetShareEnum response parameters'
        end
        params = Response.read(params_bytes)
        unless params.status.zero?
          raise RubySMB::Error::RubySMBError,
                "RAP NetShareEnum failed with status 0x#{params.status.to_i.to_s(16)}"
        end

        data_bytes = response.data_block.trans_data.to_s
        params.entry_count.times.map do |i|
          offset = i * ShareInfo1.new.num_bytes
          break [] if offset + ShareInfo1.new.num_bytes > data_bytes.bytesize
          entry = ShareInfo1.read(data_bytes[offset, ShareInfo1.new.num_bytes])
          {
            name: entry.netname.to_s.delete("\x00"),
            type: entry.share_type
          }
        end.compact
      end
    end
  end
end
