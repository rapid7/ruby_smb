module RubySMB
  module Dcerpc
    module Winreg

      # This class represents a REGSAM structure as defined in
      # [2.2.3 REGSAM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/fefbc801-b141-4bb1-9dcb-bf366da3ae7e)
      # [2.4.3 ACCESS_MASK](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b)
      class Regsam < BinData::Record
        endian  :little
        bit2    :reserved,               label: 'Reserved Space'
        bit1    :key_create_link,        label: 'Key Create Link'
        bit1    :key_notify,             label: 'Key Notify'
        bit1    :key_enumerate_sub_keys, label: 'Key Enumerate Sub Keys'
        bit1    :key_create_sub_key,     label: 'Key Create Sub Key'
        bit1    :key_set_value,          label: 'Key Set Value'
        bit1    :key_query_value,        label: 'Key Query Value'
        # byte boundary
        bit6    :reserved2,              label: 'Reserved Space'
        bit1    :key_wow64_32key,        label: 'Key Wow64 32key'
        bit1    :key_wow64_64key,        label: 'Key Wow64 64key'
        # byte boundary
        bit3    :reserved3,              label: 'Reserved Space'
        bit1    :synchronize,            label: 'Synchronize'
        bit1    :write_owner,            label: 'Write Owner'
        bit1    :write_dac,              label: 'Write DAC'
        bit1    :read_control,           label: 'Read Control'
        bit1    :delete_access,          label: 'Delete'
        # byte boundary
        bit1    :generic_read,           label: 'Generic Read'
        bit1    :generic_write,          label: 'Generic Write'
        bit1    :generic_execute,        label: 'Generic Execute'
        bit1    :generic_all,            label: 'Generic All'
        bit2    :reserved4,              label: 'Reserved Space'
        bit1    :maximum,                label: 'Maximum Allowed'
        bit1    :system_security,        label: 'System Security'
      end

    end
  end
end
