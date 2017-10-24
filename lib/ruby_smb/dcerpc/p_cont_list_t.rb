module RubySMB
  module Dcerpc
    # The FileDirectoryInformation Class as defined in
    # [2.4.18 FileIdFullDirectoryInformation](https://msdn.microsoft.com/en-us/library/cc232071.aspx)
    class PContListT < BinData::Record
      endian :little

      uint8           :n_context_elem,    label: 'number of items', initial_value: 2
      uint8           :reserved,          label: 'alignment pad, m.b.z.'
      uint16          :reserved2,         label: 'alignment pad, m.b.z.'
      string          :p_cont_elem_array, label: 'p_cont_elem array'
    end
  end
end
