module RubySMB
  module Dcerpc
    # The FileDirectoryInformation Class as defined in
    # [2.4.18 FileIdFullDirectoryInformation](https://msdn.microsoft.com/en-us/library/cc232071.aspx)
    class PContElemT < BinData::Record
      endian :little

      uint16           :p_cont_id,         label: 'constant id'
      uint8            :n_transfer_syn,    label: 'number of items', initial_value: 1
      uint8            :reserved,          label: 'alignment pad, m.b.z.'
      string           :abstract_syntax,   label: 'transfer syntax list'
      string           :transfer_syntaxes, label: 'transfer syntaxes'
    end
  end
end
