module RubySMB
  module SMB2

    class PreauthIntegrityCapabilities < BinData::Record
      SHA_512 = 0x0001

      endian  :little

      uint16 :hash_algorithm_count, label: 'Hash Algorithm Count', initial_value: -> { hash_algorithms.size }
      uint16 :salt_length,          label: 'Salt Length',          initial_value: -> { salt.num_bytes }
      array  :hash_algorithms,      label: 'Hash Algorithms',      type: :uint16, initial_length: -> { hash_algorithm_count }
      string :salt,                 label: 'Salt',                 read_length: -> { salt_length }
    end

    class EncryptionCapabilities < BinData::Record
      AES_128_CCM = 0x0001
      AES_128_GCM = 0x0002

      endian  :little

      uint16 :cipher_count, label: 'Cipher Count', initial_value: -> { ciphers.size }
      array  :ciphers,      label: 'Ciphers',      type: :uint16, initial_length: -> { cipher_count }
    end

    class CompressionCapabilities < BinData::Record
      # Flags
      # Chained compression is not supported.
      SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE    = 0x00000000
      # Chained compression is supported on this connection.
      SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED = 0x00000001

      # Compression Algorithms
      NONE         = 0x0000
      LZNT1        = 0x0001
      LZ77         = 0x0002
      LZ77_Huffman = 0x0003
      Pattern_V1   = 0x0004

      endian  :little

      uint16 :compression_algorithm_count, label: 'Compression Algorithm Count', initial_value: -> { compression_algorithms.size }
      uint16 :padding,                     label: 'Padding',                     initial_value: 0
      uint32 :flags,                       label: 'Flags'
      array  :compression_algorithms,      label: 'Compression Algorithms',      type: :uint16, initial_length: -> { compression_algorithm_count }
    end

    class NetnameNegotiateContextId < BinData::Record
      endian  :little

      stringz16 :net_name, label: 'Net Name'
    end


    # An SMB2 NEGOTIATE_CONTEXT struct as defined in
    # [2.2.3.1 SMB2 NEGOTIATE_CONTEXT Request Values](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7)
    class NegotiateContext < BinData::Record
      # The NegotiateContext Data field contains a list of preauthentication integrity hash functions as well as an optional salt value, as specified in section 2.2.3.1.1.
      SMB2_PREAUTH_INTEGRITY_CAPABILITIES  = 0x0001
      # The NegotiateContext Data field contains a list of encryption algorithms, as specified in section 2.2.3.1.2.
      SMB2_ENCRYPTION_CAPABILITIES         = 0x0002
      # The NegotiateContext Data field contains a list of compression algorithms, as specified in section 2.2.3.1.3.
      SMB2_COMPRESSION_CAPABILITIES        = 0x0003
      # The NegotiateContext Data field contains the server name to which the client connects.
      SMB2_NETNAME_NEGOTIATE_CONTEXT_ID    = 0x0005

      endian  :little

      # Constants defined in RubySMB::SMB2::ContextType
      uint16 :context_type, label: 'Context Type'
      uint16 :data_length,  label: 'Data Length', initial_value: -> { data.num_bytes }
      uint32 :reserved,     label: 'Reserved',    initial_value: 0
      choice :data,         label: 'Data',        selection: -> { context_type } do
        preauth_integrity_capabilities SMB2_PREAUTH_INTEGRITY_CAPABILITIES, label: 'Preauthentication Integrity Capabilities'
        encryption_capabilities        SMB2_ENCRYPTION_CAPABILITIES,        label: 'Encryption Capabilities'
        compression_capabilities       SMB2_COMPRESSION_CAPABILITIES,       label: 'Compression Capabilities'
        netname_negotiate_context_id   SMB2_NETNAME_NEGOTIATE_CONTEXT_ID,   label: 'Netname Negotiate Context ID'
      end
      string :pad, label: 'Padding', length: -> { pad_length }, onlyif: -> { need_padding? }

      def pad_length
        offset = pad.abs_offset % 8
        (8 - offset) % 8
      end

      def need_padding?
        # Padding is needed to make sure the next NegotiateContext structure
        # is 8-bytes aligned. No padding is needed if this structure is the
        # last one or if it is the only one.
        return !self.equal?(self.parent.last)
      rescue NoMethodError
        # This structure is not part of an BinData::Array, no padding needed
        return false
      end

    end
  end
end
