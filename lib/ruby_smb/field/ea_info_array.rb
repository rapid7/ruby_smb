module RubySMB
  module Field
    # Convenience class that extend the normal {BinData::Array} for use
    # with {RubySMB::Field::FileFullEaInfo}. This array will automatically
    # updates the {RubySMB::Field::FileFullEaInfo#next_entry_offset} of
    # each element in the array.
    class EaInfoArray < BinData::Array

      # Overrides the method from {BinData::Array} to
      # call #update_offsets
      # @raise [ArgumentError] if the inserted element is not a {RubySMB::Field::FileFullEaInfo}
      def []=(index, value)
        unless value.is_a? RubySMB::Field::FileFullEaInfo
          raise ArgumentError, "This array can only contain RubySMB::Field::FileFullEaInfo objects"
        end
        retval = super(index,value)
        update_offsets
        retval
      end

      # Overrides the insert method in {BinData::Array} to
      # call #update_offsets.
      #
      # @param index [Integer] the index to insert into the array at
      # @param objs [Array<Object>] the objects to be inserted
      # @raise [ArgumentError] if the inserted element is not a {RubySMB::Field::FileFullEaInfo}
      # @return [self]
      def insert(index, *objs)
        objs.each do |x|
          unless x.is_a? RubySMB::Field::FileFullEaInfo
            raise ArgumentError, "This array can only contain RubySMB::Field::FileFullEaInfo objects"
          end
        end
        super(index, *objs)
        update_offsets
      end

      # Iterates through all of the elements in the array and
      # dynamically updates all of the next_record_offset fields
      # to properly reflect the chain.
      #
      # @return [self]
      def update_offsets
        self.each do |element|
          if element == self.last
            # If this is the end of our array, the offset must be 0
            element.next_entry_offset = 0
          else
            # If there is an element after this one, set the offset
            element.next_entry_offset = element.do_num_bytes
          end
        end
        self
      end

    end
  end
end
