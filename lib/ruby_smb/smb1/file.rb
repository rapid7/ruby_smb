module RubySMB
  module SMB1
    # Represents a file on the Remote server that we can perform
    # various I/O operations on.
    class File
      # The {RubySMB::SMB1::Tree} that this file belong to
      # @!attribute [rw] tree
      #   @return [RubySMB::SMB1::Tree]
      attr_accessor :tree

      # The name of the file
      # @!attribute [rw] name
      #   @return [String]
      attr_accessor :name

      # The {SmbExtFileAttributes} for the file
      # @!attribute [rw] attributes
      #   @return [RubySMB::SMB1::BitField::SmbExtFileAttributes]
      attr_accessor :attributes

      # The file ID
      # @!attribute [rw] fid
      #   @return [Integer]
      attr_accessor :fid

      # The last access date/time for the file
      # @!attribute [rw] last_access
      #   @return [DateTime]
      attr_accessor :last_access

      # The last change date/time for the file
      # @!attribute [rw] last_change
      #   @return [DateTime]
      attr_accessor :last_change

      # The last write date/time for the file
      # @!attribute [rw] last_write
      #   @return [DateTime]
      attr_accessor :last_write

      # The actual size, in bytes, of the file
      # @!attribute [rw] size
      #   @return [Integer]
      attr_accessor :size

      # The size in bytes that the file occupies on disk
      # @!attribute [rw] size_on_disk
      #   @return [Integer]
      attr_accessor :size_on_disk

      def initialize(tree:, response:, name:)
        raise ArgumentError, 'No tree provided' if tree.nil?
        raise ArgumentError, 'No response provided' if response.nil?
        raise ArgumentError, 'No file name provided' if name.nil?

        @tree = tree
        @name = name

        @attributes   = response.parameter_block.ext_file_attributes
        @fid          = response.parameter_block.fid
        @last_access  = response.parameter_block.last_access_time.to_datetime
        @last_change  = response.parameter_block.last_change_time.to_datetime
        @last_write   = response.parameter_block.last_write_time.to_datetime
        @size         = response.parameter_block.end_of_file
        @size_on_disk = response.parameter_block.allocation_size
      end

      # Appends the supplied data to the end of the file.
      #
      # @param data [String] the data to write to the file
      # @return [WindowsError::ErrorCode] the NTStatus code returned from the operation
      def append(data:)
        write(data: data, offset: @size)
      end

      # Closes the handle to the remote file.
      #
      # @return [WindowsError::ErrorCode] the NTStatus code returned by the operation
      def close
        close_request = set_header_fields(RubySMB::SMB1::Packet::CloseRequest.new)
        raw_response  = @tree.client.send_recv(close_request)
        response = @tree.client.parse_response(response_packet: RubySMB::SMB1::Packet::CloseResponse, raw_response: raw_response)
        response.status_code
      end

      # Read from the file, a specific number of bytes
      # from a specific offset. If no parameters are given
      # it will read the entire file.
      #
      # @param bytes [Integer] the number of bytes to read
      # @param offset [Integer] the byte offset in the file to start reading from
      # @return [String] the data read from the file
      def read(bytes: @size, offset: 0)
        atomic_read_size = if bytes > @tree.client.max_buffer_size
                             @tree.client.max_buffer_size
                           else
                             bytes
                           end
        remaining_bytes = bytes
        data = ''

        loop do
          read_request = read_packet(read_length: atomic_read_size, offset: offset)
          raw_response = @tree.client.send_recv(read_request)
          response = @tree.client.parse_response(response_packet: RubySMB::SMB1::Packet::ReadAndxResponse, raw_response: raw_response)

          if response.is_a?(RubySMB::SMB1::Packet::ReadAndxResponse)
            data << response.data_block.data.to_binary_s
          else
            # Returns the current data immediately if we got an empty packet with an
            # SMB_COM_READ_ANDX command and a STATUS_SUCCESS (just in case)
            return data
          end

          remaining_bytes -= atomic_read_size
          break unless remaining_bytes > 0

          offset += atomic_read_size
          atomic_read_size = remaining_bytes if remaining_bytes < @tree.client.max_buffer_size
        end

        data
      end

      # Crafts the ReadRequest packet to be sent for read operations.
      #
      # @param bytes [Integer] the number of bytes to read
      # @param offset [Integer] the byte offset in the file to start reading from
      # @return [RubySMB::SMB1::Packet::ReadAndxRequest] the crafted ReadRequest packet
      def read_packet(read_length: 0, offset: 0)
        read_request = set_header_fields(RubySMB::SMB1::Packet::ReadAndxRequest.new)
        read_request.parameter_block.max_count_of_bytes_to_return = read_length
        read_request.parameter_block.offset = offset
        read_request
      end

      # Write the supplied data to the file at the given offset.
      #
      # @param data [String] the data to write to the file
      # @param offset [Integer] the offset in the file to start writing from
      # @return [WindowsError::ErrorCode] the NTStatus code returned from the operation
      def write(data:, offset: 0)
        buffer = data.dup
        bytes  = data.length
        status = nil

        loop do
          atomic_write_size = if bytes > @tree.client.max_buffer_size
                               @tree.client.max_buffer_size
                              else
                                bytes
                              end
          write_request = write_packet(data: buffer.slice!(0, atomic_write_size), offset: offset)
          raw_response = @tree.client.send_recv(write_request)
          response = @tree.client.parse_response(response_packet: RubySMB::SMB1::Packet::WriteAndxResponse, raw_response: raw_response)
          status = response.status_code
          offset += atomic_write_size
          bytes -= atomic_write_size
          return status unless status == WindowsError::NTStatus::STATUS_SUCCESS
          break unless buffer.length > 0
        end

        status
      end

      # Creates the Request packet for the #write command
      #
      # @param data [String] the data to write to the file
      # @param offset [Integer] the offset in the file to start writing from
      # @return [RubySMB::SMB1::Packet::WriteAndxRequest] the request packet
      def write_packet(data:'', offset: 0)
        write_request = set_header_fields(RubySMB::SMB1::Packet::WriteAndxRequest.new)
        write_request.parameter_block.offset = offset
        write_request.parameter_block.write_mode.writethrough_mode = 1
        write_request.data_block.data = data
        write_request.parameter_block.remaining = write_request.parameter_block.data_length
        write_request
      end

      # Sets the header fields that we have to set on every packet
      # we send for File operations.
      #
      # @param request [RubySMB::GenericPacket] the request packet to set fields on
      # @return [RubySMB::GenericPacket] the modified request packet
      def set_header_fields(request)
        request = @tree.set_header_fields(request)
        request.parameter_block.fid = @fid
        request
      end

    end
  end
end
