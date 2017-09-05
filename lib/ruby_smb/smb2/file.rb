module RubySMB
  module SMB2
    # Represents a file on the Remote server that we can perform
    # various I/O operations on.
    class File
      # The maximum number of byte we want to read in a
      # single packet.
      MAX_READ_SIZE = 32_768

      # The {FileAttributes} for the file
      # @!attribute [rw] attributes
      #   @return [RubySMB::Fscc::FileAttributes]
      attr_accessor :attributes

      # The {Smb2FileId} for the file
      # @!attribute [rw] guid
      #   @return [RubySMB::Field::Smb2FileId]
      attr_accessor :guid

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

      # The name of the file
      # @!attribute [rw] name
      #   @return [String]
      attr_accessor :name

      # The actual size, in bytes, of the file
      # @!attribute [rw] size
      #   @return [Integer]
      attr_accessor :size

      # The size in bytes that the file occupies on disk
      # @!attribute [rw] size_on_disk
      #   @return [Integer]
      attr_accessor :size_on_disk

      # The {RubySMB::SMB2::Tree} that this file belong to
      # @!attribute [rw] tree
      #   @return [RubySMB::SMB2::Tree]
      attr_accessor :tree

      def initialize(tree:, response:, name:)
        raise ArgumentError, 'No Tree Provided' if tree.nil?
        raise ArgumentError, 'No Response Provided' if response.nil?

        @tree = tree
        @name = name

        @attributes   = response.file_attributes
        @guid         = response.file_id
        @last_access  = response.last_access.to_datetime
        @last_change  = response.last_change.to_datetime
        @last_write   = response.last_write.to_datetime
        @size         = response.end_of_file
        @size_on_disk = response.allocation_size
      end

      # Closes the handle to the remote file.
      #
      # @return [WindowsError::ErrorCode] the NTStatus code returned by the operation
      def close
        close_request = set_header_fields(RubySMB::SMB2::Packet::CloseRequest.new)
        raw_response  = tree.client.send_recv(close_request)
        response = RubySMB::SMB2::Packet::CloseResponse.read(raw_response)
        response.smb2_header.nt_status.to_nt_status
      end

      # Read from the file, a specific number of bytes
      # from a specific offset. If no parameters are given
      # it will read the entire file.
      #
      # @param bytes [Integer] the number of bytes to read
      # @param offset [Integer] the byte offset in the file to start reading from
      # @return [String] the data read from the file
      def read(bytes: size, offset: 0)
        atomic_read_size = if bytes > MAX_READ_SIZE
                             MAX_READ_SIZE
                           else
                             bytes
                           end

        read_request = read_packet(read_length: atomic_read_size, offset: offset)
        raw_response = tree.client.send_recv(read_request)
        response     = RubySMB::SMB2::Packet::ReadResponse.read(raw_response)

        data = response.buffer.to_binary_s

        remaining_bytes = bytes - atomic_read_size

        while remaining_bytes.positive?
          offset += atomic_read_size
          atomic_read_size = remaining_bytes if remaining_bytes < MAX_READ_SIZE

          read_request = read_packet(read_length: atomic_read_size, offset: offset)
          raw_response = tree.client.send_recv(read_request)
          response     = RubySMB::SMB2::Packet::ReadResponse.read(raw_response)

          data << response.buffer.to_binary_s
          remaining_bytes -= atomic_read_size
        end
        data
      end

      # Crafts the ReadRequest packet to be sent for read operations.
      #
      # @param bytes [Integer] the number of bytes to read
      # @param offset [Integer] the byte offset in the file to start reading from
      # @return [RubySMB::SMB2::Packet::ReadRequest] the data read from the file
      def read_packet(read_length: 0, offset: 0)
        read_request = set_header_fields(RubySMB::SMB2::Packet::ReadRequest.new)
        read_request.read_length  = read_length
        read_request.offset       = offset
        read_request
      end

      def set_header_fields(request)
        request         = tree.set_header_fields(request)
        request.file_id = guid
        request
      end
    end
  end
end
