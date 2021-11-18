module RubySMB
  module SMB2
    # An SMB2_CREATE_CONTEXT struct as defined in
    # [2.2.13.2 SMB2_CREATE_CONTEXT Request Values](https://msdn.microsoft.com/en-us/library/cc246504.aspx)
    class CreateContext < BinData::Record
      auto_call_delayed_io
      endian  :little

      uint32  :next_offset, label: 'Offset to next Context'
      uint16  :name_offset, label: 'Offset to Name/Tag',      initial_value:  -> { name.rel_offset }
      uint16  :name_length, label: 'Length of Name/Tag',      initial_value:  -> { name.length }
      uint16  :reserved,    label: 'Reserved Space'
      uint16  :data_offset, label: 'Offset to data',          initial_value:  -> { calc_data_offset }
      uint32  :data_length, label: 'Length of data',          initial_value:  -> { data.length }

      delayed_io :name, read_abs_offset: -> { abs_offset + name_offset } do
        string  :name,      label: 'Name', read_length: :name_length
      end
      delayed_io :data, read_abs_offset: -> { abs_offset + data_offset } do
        string  :data,      label: 'Data', read_length: :data_length
      end

      # use skip to ensure the stream position is correct, next_offset is 0 for the last entry
      skip :padding, length: -> { next_offset == 0 ? 0 : next_offset - padding.rel_offset }

      private

      def calc_data_offset
        if data.empty?
          0
        else
          data.rel_offset
        end
      end
    end

    class CreateContextArray < BinData::Array
      include BinData::Base::AutoCallDelayedIO

      endian :little

      default_parameters type: :create_context
      default_parameters read_until: -> { @obj&.last.next_offset == 0 }
    end
  end
end
