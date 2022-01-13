module RubySMB
  module SMB2
    module Packet
      # An SMB2 TreeConnectResponse Packet as defined in
      # [2.2.10 SMB2 TREE_CONNECT Response](https://msdn.microsoft.com/en-us/library/cc246499.aspx)
      class TreeConnectResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::TREE_CONNECT

        # Share Types
        # Physical disk share
        SMB2_SHARE_TYPE_DISK  = 0x01
        # Named pipe share
        SMB2_SHARE_TYPE_PIPE  = 0x02
        # Printer share
        SMB2_SHARE_TYPE_PRINT = 0x03

        endian :little
        smb2_header           :smb2_header
        uint16                :structure_size, label: 'Structure Size', initial_value: 16
        uint8                 :share_type,     label: 'Share Type',     initial_value: 0x01
        uint8                 :reserved,       label: 'Reserved Space', initial_value: 0x00
        share_flags           :share_flags
        share_capabilities    :capabilities
        file_access_mask      :maximal_access, label: 'Maximal Access'

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end

      end
    end
  end
end
