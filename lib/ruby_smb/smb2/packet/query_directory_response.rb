module RubySMB
  module SMB2
    module Packet

      # An SMB2 Query Directory Response Packet as defined in
      # [2.2.34 SMB2 QUERY_DIRECTORY Response](https://msdn.microsoft.com/en-us/library/cc246552.aspx)
      class QueryDirectoryResponse < RubySMB::GenericPacket
        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size,  label: 'Structure Size',       initial_value: 9
        uint16       :buffer_offset,   label: 'Output Buffer Offset', initial_value: lambda { buffer.abs_offset }
        uint32       :buffer_length,   label: 'Output Buffer Length', initial_value: lambda { buffer.do_num_bytes }
        string       :buffer

        def initialize_instance
          super
          smb2_header.command = RubySMB::SMB2::Commands::QUERY_DIRECTORY
          smb2_header.flags.reply = 1
        end

      end
    end
  end
end