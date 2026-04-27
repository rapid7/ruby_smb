module RubySMB
  module SMB1
    module Packet
      module Trans2
        # Shared workaround for pre-NT / LAN Manager-era servers (observed on
        # Windows 9x / ME) that pack `trans2_parameters` directly after
        # `byte_count` with no 4-byte-alignment pad, and `trans2_data` with
        # whatever padding they feel like — always smaller than the NT-style
        # alignment BinData unconditionally assumes via {DataBlock#pad1_length}
        # and {DataBlock#pad2_length}. When that happens both sections land in
        # the wrong place and `eos`, `sid`, `last_name_offset`, and every
        # entry in the data buffer come back garbled.
        #
        # Fixing this in BinData itself (by having pad1/pad2 consult
        # `parameter_block.parameter_offset` / `data_offset`) is the natural
        # design, but cross-field lookups during field-read callbacks corrupt
        # BinData's registered-class resolution cache, causing unrelated
        # Trans2 responses to round-trip their `parameter_block` / `data_block`
        # through the base classes instead of the concrete subclasses. So
        # instead we surface the raw response bytes at the call site and let
        # the response slice both sections from the offsets the server
        # reported in its `parameter_block`.
        #
        # Mix into any {RubySMB::SMB1::Packet::Trans2} response whose caller
        # holds on to the raw response bytes. The response itself must have
        # the standard {Trans2::Response::ParameterBlock} shape
        # (`parameter_offset` / `parameter_count` / `data_offset` /
        # `data_count`) and a `data_block` with `trans2_parameters` and
        # `trans2_data.buffer` fields — every concrete Trans2 response does.
        #
        # Same slicing pattern as {RubySMB::Rap::NetShareEnum#parse_net_share_enum_response}
        # uses for the sibling Trans (not Trans2) response type.
        module Win9xFraming
          # Returns `[effective_trans2_parameters, effective_trans2_data_bytes]`
          # when the server's layout differs from BinData's, or `[nil, nil]`
          # when BinData already read the full buffer (standard NT-era servers).
          #
          # When a non-nil pair is returned, callers should prefer the override
          # values over the BinData-parsed ones:
          #
          #   params_ovr, data_ovr = response.win9x_trans2_overrides(raw)
          #   params = params_ovr || response.data_block.trans2_parameters
          #   data   = data_ovr   || response.data_block.trans2_data.buffer.to_binary_s
          #
          # @param raw_response [String] the raw bytes the response was read from.
          # @return [Array(BinData::Record, String), Array(nil, nil)]
          def win9x_trans2_overrides(raw_response)
            declared_data = parameter_block.data_count.to_i
            parsed_data   = data_block.trans2_data.buffer.to_binary_s.bytesize
            return [nil, nil] if declared_data.zero? || parsed_data == declared_data

            param_offset = parameter_block.parameter_offset.to_i
            param_count  = parameter_block.parameter_count.to_i
            data_offset  = parameter_block.data_offset.to_i
            return [nil, nil] if raw_response.bytesize < data_offset + declared_data
            return [nil, nil] if raw_response.bytesize < param_offset + param_count

            params_bytes = raw_response.byteslice(param_offset, param_count)
            params_class = data_block.trans2_parameters.class
            params       = params_class.read(params_bytes)
            data_bytes   = raw_response.byteslice(data_offset, declared_data)
            [params, data_bytes]
          end
        end
      end
    end
  end
end
