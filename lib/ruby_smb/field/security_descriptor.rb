module RubySMB
  module Field
    # Class representing a SECURITY_DESCRIPTOR as defined in
    # [2.4.6 SECURITY_DESCRIPTOR](https://msdn.microsoft.com/en-us/library/cc230366.aspx)
    class SecurityDescriptor < BinData::Record

      # Security Information as defined in
      # [2.4.7 SECURITY_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/23e75ca3-98fd-4396-84e5-86cd9d40d343)
      OWNER_SECURITY_INFORMATION               = 0x00000001
      GROUP_SECURITY_INFORMATION               = 0x00000002
      DACL_SECURITY_INFORMATION                = 0x00000004
      SACL_SECURITY_INFORMATION                = 0x00000008
      LABEL_SECURITY_INFORMATION               = 0x00000010
      UNPROTECTED_SACL_SECURITY_INFORMATION    = 0x10000000
      UNPROTECTED_DACL_SECURITY_INFORMATION    = 0x20000000
      PROTECTED_SACL_SECURITY_INFORMATION      = 0x40000000
      PROTECTED_DACL_SECURITY_INFORMATION      = 0x80000000
      ATTRIBUTE_SECURITY_INFORMATION           = 0x00000020
      SCOPE_SECURITY_INFORMATION               = 0x00000040
      PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080
      BACKUP_SECURITY_INFORMATION              = 0x00010000

      endian  :little
      uint8   :revision,  label: 'Revision', initial_value: 0x01
      uint8   :sbz1,      label: 'Resource Manager Control Bits'

      # The Control field is an unsigned 16-bit value transmitted little-endian.
      # MS-DTYP 2.4.6 numbers the bits most-significant-first, so the low byte
      # (read first) carries SS..OD and the high byte (read second) carries
      # SR..DC. The bit1 fields are therefore declared most-significant-first
      # within each byte: low byte first, then high byte. This keeps each flag
      # mapped to the bit value defined by MS-DTYP (for example SR/self_relative
      # is 0x8000 and DP/dacl_present is 0x0004).
      struct :control do
        endian  :little
        # Low byte (first byte read), most-significant bit first.
        bit1    :server_security,           label: 'Server Security'           # 0x0080
        bit1    :dacl_trusted,              label: 'DACL Trusted'              # 0x0040
        bit1    :sacl_defaulted,            label: 'SACL Defaulted'            # 0x0020
        bit1    :sacl_present,              label: 'SACL Present'              # 0x0010
        bit1    :dacl_defaulted,            label: 'DACL Defaulted'            # 0x0008
        bit1    :dacl_present,              label: 'DACL Present'              # 0x0004
        bit1    :group_defaulted,           label: 'Group Defaulted'          # 0x0002
        bit1    :owner_defaulted,           label: 'Owner Defaulted'          # 0x0001
        # High byte (second byte read), most-significant bit first.
        bit1    :self_relative,             label: 'Self-Relative Format', initial_value: 0x01 # 0x8000
        bit1    :rm_control_valid,          label: 'RM Control Valid'          # 0x4000
        bit1    :sacl_protected,            label: 'SACL Protected'            # 0x2000
        bit1    :dacl_protected,            label: 'DACL Protected'            # 0x1000
        bit1    :sacl_auto_inherited,       label: 'SACL Auto-Inherited'       # 0x0800
        bit1    :dacl_auto_inherited,       label: 'DACL Auto-Inherited'       # 0x0400
        bit1    :sacl_computed_inheritance, label: 'SACL Computed Inheritance' # 0x0200
        bit1    :dacl_computed_inheritance, label: 'DACL Computed Inheritance' # 0x0100
      end

      uint32  :offset_owner,  label: 'Offset Owner',  initial_value: -> { owner_sid.rel_offset }
      uint32  :offset_group,  label: 'Offset Group',  initial_value: -> { group_sid.rel_offset }
      uint32  :offset_sacl,   label: 'Offset SACL',   initial_value: -> { sacl.rel_offset }
      uint32  :offset_dacl,   label: 'Offset DACL',   initial_value: -> { dacl.rel_offset }

      string  :owner_sid, label: 'Owner SID'
      string  :group_sid, label: 'Group SID'
      string  :sacl,      label: 'SACL'
      string  :dacl,      label: 'DACL'
    end
  end
end
