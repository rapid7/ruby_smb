module RubySMB
  module SMB2

    # Represents a file on the Remote server that we can perform
    # various I/O operations on.
    class File

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
        @last_access  = response.last_access
        @last_change  = response.last_chnge
        @last_write   = response.last_write
        @size         = response.end_of_file
        @size_on_disk = response.allocation_size
      end

    end
  end
end