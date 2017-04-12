module RubySMB
  module SMB2
    module Packet

      # An SMB2 TreeConnectResponse Packet as defined in
      # [2.2.10 SMB2 TREE_CONNECT Response](https://msdn.microsoft.com/en-us/library/cc246499.aspx)
      class TreeConnectResponse < RubySMB::GenericPacket
        endian  :little
        smb2_header           :smb2_header
        uint16                :structure_size, label: 'Structure Size', initial_value: 16
        uint8                 :share_type,     label: 'Share Type',     initial_value: 0x01
        uint8                 :reserved,       label: 'Reserved Space', initial_value: 0x00
        share_flags           :share_flags
        share_capabilities    :capabilities
        directory_access_mask :maximal_access, label: 'Maximal Access'

        def initialize_instance
          super
          smb2_header.command = RubySMB::SMB2::Commands::TREE_CONNECT
          smb2_header.flags.reply = 1
        end

        # Returns the ACCESS_MASK for the Maximal Share Access Rights. The packet
        # defaults this to a {RubySMB::SMB2::BitField::DirectoryAccessMask}. If it is anything other than
        # a directory that has been connected to, it will re-cast it as a {RubySMB::SMB2::BitField::FileAccessMask}
        #
        # @return [RubySMB::SMB2::BitField::DirectoryAccessMask] if a directory was connected to
        # @return [RubySMB::SMB2::BitField::FileAccessMask] if anything else was connected to
        def access_rights
          if is_directory?
            self.maximal_access
          else
            mask = self.maximal_access.to_binary_s
            RubySMB::SMB2::BitField::FileAccessMask.read(mask)
          end
        end

        # Checks if the remote Tree is a directory
        #
        # @return [Boolean]
        def is_directory?
          self.share_type == 0x01
        end



      end
    end
  end
end