module RubySMB
  module SMB1
    module BitField
      # The bit-field for SMB1 Extended File Attributes as defined in
      # [2.2.1.2.3 SMB_EXT_FILE_ATTR](https://msdn.microsoft.com/en-us/library/ee878573.aspx)
      class SmbExtFileAttributes < BinData::Record
        endian  :little
        bit1  :normal,            label: 'Normal File'
        bit1  :reserved,          label: 'Reserved Space'
        bit1  :archive,           label: 'Archive'
        bit1  :directory,         label: 'Directory'
        bit1  :reserved2,         label: 'Reserved Space'
        bit1  :system,            label: 'System File'
        bit1  :hidden,            label: 'Hidden File'
        bit1  :read_only,         label: 'Read Only'
        # Byte boundary
        bit4  :reserved3,         label: 'Reserved Space'
        bit1  :compressed,        label: 'Compressed File'
        bit2  :reserved4,         label: 'Reserved Space'
        bit1  :temporary,         label: 'Temporary File'
        # Byte Boundary
        bit8  :reserved5,         label: 'Reserved Space'
        # Byte Boundary
        bit1  :write_through,     label: 'Write through'
        bit1  :reserved6,         label: 'Reserved Space'
        bit1  :no_buffering,      label: 'Do not Buffer'
        bit1  :random_access,     label: 'Random Access'
        bit1  :sequential_scan,   label: 'Sequential Access'
        bit1  :delete_on_close,   label: 'Delete on close'
        bit1  :backup_semantics,  label: 'Backup Semantics'
        bit1  :posix_semantics,   label: 'POSIX Semantics'
      end
    end
  end
end
