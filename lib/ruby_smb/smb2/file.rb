module RubySMB
  module SMB2

    # Represents a file on the Remote server that we can perform
    # various I/O operations on.
    class File

      # The maximum number of byte we want to read in a
      # single packet.
      MAX_READ_SIZE = 32768

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

      def initialize(tree:,response:, name:)
        raise ArgumentError, "No Tree Provided" if tree.nil?
        raise ArgumentError, "No Response Provided" if response.nil?

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

      # Read from the file, a specific number of bytes
      # from a specific offset. If no parameters are given
      # it will read the entire file.
      #
      # @param bytes [Integer] the number of bytes to read
      # @param offset [Integer] the byte offset in the file to start reading from
      # @return [String] the data read from the file
      def read(bytes: self.size, offset: 0)
        read_request = RubySMB::SMB2::Packet::ReadRequest.new

        read_request          = tree.set_header_fields(read_request)
        read_request.file_id  = self.guid

        if bytes > MAX_READ_SIZE
          atomic_read_size = MAX_READ_SIZE
        else
          atomic_read_size = bytes
        end

        read_request.read_length  = atomic_read_size
        read_request.offset       = offset

        raw_response = self.tree.client.send_recv(read_request)
        response     = RubySMB::SMB2::Packet::ReadResponse.read(raw_response)

        data = response.buffer
      end

    end
  end
end