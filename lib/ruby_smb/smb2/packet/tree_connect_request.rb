module RubySMB
  module SMB2
    module Packet

      # An SMB2 TreeConnectRequest Packet as defined in
      # [2.2.9 SMB2 TREE_CONNECT Request](https://msdn.microsoft.com/en-us/library/cc246567.aspx)
      class TreeConnectRequest < RubySMB::GenericPacket
        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 9
        uint16       :flags,          label: 'Flags',          initial_value: 0x00
        uint16       :path_offset,    label: 'Path Offset',    initial_value: 0x48
        uint16       :path_length,    label: 'Path Length',    initial_value: lambda { self.path.length }
        string       :path,           label: 'Path Buffer'

        def initialize_instance
          super
          smb2_header.command = RubySMB::SMB2::Commands::TREE_CONNECT
        end

        def encode_path(path)
          self.path = path.encode("utf-16le")
        end
      end
    end
  end
end