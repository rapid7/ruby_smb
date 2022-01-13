module RubySMB
  module Fscc
    module FileInformation
      # The FileStreamInformation
      # [2.4.43 FileStreamInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/f8762be6-3ab9-411e-a7d6-5cc68f70c78d)
      class FileStreamInformation < BinData::Record
        endian :little
        uint32   :next_entry_offset,      label: 'Next Entry Offset'
        uint32   :stream_name_length,     label: 'Stream Name Length', initial_value: -> { stream_name.do_num_bytes }
        int64    :stream_size,            label: 'Stream Size'
        int64    :stream_allocation_size, label: 'Stream Allocation Size'
        string16 :stream_name,            label: 'Stream Name', read_length: -> { stream_name_length }
      end
    end
  end
end
