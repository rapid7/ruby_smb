module RubySMB
  module SMB2
    module Packet
      # An SMB2 Ioctl Response Packet as defined in
      # [2.2.32 SMB2 IOCTL Response](https://msdn.microsoft.com/en-us/library/cc246548.aspx)
      class IoctlResponse < RubySMB::GenericPacket
        endian :little

        smb2_header   :smb2_header
        uint16        :structure_size,      label: 'Structure Size',      initial_value: 49
        uint16        :reserved1,           label: 'Reserved Space'
        uint32        :ctl_code,            label: 'Control Code'
        smb2_fileid   :file_id,             label: 'File Id'
        uint32        :input_offset,        label: 'Input Offset'
        uint32        :input_count,         label: 'Input Count'
        uint32        :output_offset,       label: 'Output Offset'
        uint32        :output_count,        label: 'Output Count'
        uint32        :flags,               label: 'Flags'
        uint32        :reserved2,           label: 'Reserved Space'
        string        :buffer,              label: 'Input Buffer'

        def initialize_instance
          super
          smb2_header.flags.reply = 1
          smb2_header.command     = RubySMB::SMB2::Commands::IOCTL
        end

      end
    end
  end
end
