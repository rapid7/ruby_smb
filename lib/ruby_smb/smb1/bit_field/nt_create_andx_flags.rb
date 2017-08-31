module RubySMB
  module SMB1
    module BitField
      # The Flags bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Request as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      # [2.2.4.9.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/cc246332.aspx)
      class NtCreateAndxFlags < BinData::Record
        endian  :little
        bit3    :reserved,                   label: 'Reserved Space'
        bit1    :request_extended_response,  label: 'Request Extended Response'
        bit1    :open_target_dir,            label: 'Open Target Directory'
        bit1    :request_opbatch,            label: 'Request Batch OpLock'
        bit1    :request_oplock,             label: 'Request OpLock'
        bit1    :reserved2,                  label: 'Reserved Space'
        # Byte boundary
        bit8    :reserved3,                  label: 'Reserved Space'
        bit8    :reserved4,                  label: 'Reserved Space'
        bit8    :reserved5,                  label: 'Reserved Space'
      end
    end
  end
end
