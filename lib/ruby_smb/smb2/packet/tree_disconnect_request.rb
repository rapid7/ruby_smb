module RubySMB
  module SMB2
    module Packet
      # An SMB2 TreeDisconnectRequest Packet as defined in
      # [2.2.11 SMB2 TREE_DISCONNECT Request](https://msdn.microsoft.com/en-us/library/cc246500.aspx)
      class TreeDisconnectRequest < RubySMB::GenericPacket
        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 4

        def initialize_instance
          super
          smb2_header.command = RubySMB::SMB2::Commands::TREE_DISCONNECT
        end
      end
    end
  end
end
