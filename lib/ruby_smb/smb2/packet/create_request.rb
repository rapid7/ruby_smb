module RubySMB
  module SMB2
    module Packet

      # An SMB2 Create Request Packet as defined in
      # [2.2.13 SMB2 CREATE Request](https://msdn.microsoft.com/en-us/library/cc246502.aspx)
      class CreateRequest < RubySMB::GenericPacket
        endian       :little
        smb2_header       :smb2_header
        uint16            :structure_size,       label: 'Structure Size',              initial_value: 4
        uint8             :security_flag,        label: 'Security Flags(Do not Use)',  initial_value: 0
        uint8             :requested_oplock,     label: 'Requested OpLock Level',      initial_value: 0
        uint32            :impersonation_level,  label: 'Impersonation Level'
        uint64            :create_flags,         label: 'Create Flags(Do not use)',    initial_value: 0
        uint64            :reserved,             label: 'Reserved',                    initial_value: 0
        file_access_mask  :desired_access,       label: 'Desired Access'


        def initialize_instance
          super
          smb2_header.command = RubySMB::SMB2::Commands::CREATE
        end

      end
    end
  end
end