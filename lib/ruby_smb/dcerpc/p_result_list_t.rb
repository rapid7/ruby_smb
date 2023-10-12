module RubySMB
  module Dcerpc
    class PResultListT < Ndr::NdrStruct
      default_parameter byte_align: 4
      endian :little

      ndr_uint8  :n_results, label: 'Number of results', initial_value: -> { p_results.size }
      ndr_uint8  :reserved
      ndr_uint16 :reserved2
      array      :p_results, label: 'Results', type: :p_result_t, initial_length: -> { n_results }, byte_align: 4
    end
  end
end