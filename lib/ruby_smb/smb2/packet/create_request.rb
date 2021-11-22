module RubySMB
  module SMB2
    module Packet
      # An SMB2 Create Request Packet as defined in
      # [2.2.13 SMB2 CREATE Request](https://msdn.microsoft.com/en-us/library/cc246502.aspx)
      class CreateRequest < RubySMB::GenericPacket
        require 'ruby_smb/smb1/bit_field/create_options'
        COMMAND = RubySMB::SMB2::Commands::CREATE
        auto_call_delayed_io

        endian :little
        smb2_header           :smb2_header
        uint16                :structure_size,       label: 'Structure Size',              initial_value: 57
        uint8                 :security_flag,        label: 'Security Flags(Do not Use)',  initial_value: 0
        uint8                 :requested_oplock,     label: 'Requested OpLock Level',      initial_value: 0
        uint32                :impersonation_level,  label: 'Impersonation Level'
        uint64                :create_flags,         label: 'Create Flags(Do not use)',    initial_value: 0
        uint64                :reserved,             label: 'Reserved',                    initial_value: 0

        choice :desired_access, selection: -> { file_attributes.directory } do
          file_access_mask      0, label: 'Desired Access'
          directory_access_mask 1, label: 'Desired Access'
        end

        file_attributes :file_attributes, label: 'File Attributes'

        struct :share_access do
          bit5  :reserved,          label: 'Reserved Space'
          bit1  :delete_access,     label: 'Share Delete Access'
          bit1  :write_access,      label: 'Share Write Access'
          bit1  :read_access,       label: 'Share Read Access'
          # byte boundary
          bit8  :reserved2, label: 'Reserved Space'
          bit8  :reserved3, label: 'Reserved Space'
          bit8  :reserved4, label: 'Reserved Space'
        end

        uint32                :create_disposition, label: 'Create Disposition'
        create_options        :create_options
        uint16                :name_offset,         label: 'Name Offset'
        uint16                :name_length,         label: 'Name Length', initial_value: -> { name.num_bytes }
        uint32                :contexts_offset,     label: 'Create Contexts Offset'
        uint32                :contexts_length,     label: 'Create Contexts Length'
        count_bytes_remaining :bytes_remaining
        string                :buffer,              label: 'Buffer', initial_value: -> { build_buffer }, read_length: :bytes_remaining

        delayed_io :name, label: 'File Name', read_abs_offset: :name_offset do
          string16 read_length: :name_length
        end

        delayed_io :contexts, label: 'Context Array', read_abs_offset: :contexts_offset, onlyif: -> { contexts_offset != 0 } do
          buffer length: :contexts_length do
            create_context_array_request :contexts
          end
        end

        private

        def build_buffer
          buf = name.dup.tap { |obj| obj.abs_offset = 0 }.to_binary_s { |obj| obj.write_now! }
          buf << "\x00".b * (7 - (buf.length + 7) % 8)
          buf << contexts.map(&:to_binary_s).join
          buf << "\x00".b * (7 - (buf.length + 7) % 8)
        end
      end
    end
  end
end
