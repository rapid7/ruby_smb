module RubySMB
  module SMB2
    module Packet
      # An SMB2 Query Info Response Packet as defined in
      # [2.2.38 SMB2 QUERY_INFO Response](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b1b3598-a898-44ca-bfac-2dcae065247f)
      class QueryInfoResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::QUERY_INFO

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size,  label: 'Structure Size', initial_value: 9
        uint16       :buffer_offset,   label: 'Output Buffer Offset', initial_value: -> { buffer.empty? ? 0 : buffer.abs_offset }
        uint32       :buffer_length,   label: 'Output Buffer Length', initial_value: -> { buffer.empty? ? 0 : buffer.do_num_bytes }
        string       :buffer,          read_length: -> { buffer_length }

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
