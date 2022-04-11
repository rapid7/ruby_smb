module RubySMB
  module SMB2

    # An SMB2 PREAUTH_INTEGRITY_CAPABILITIES context struct as defined in
    # [2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5)
    class PreauthIntegrityCapabilities < BinData::Record
      SHA_512 = 0x0001
      HASH_ALGORITM_MAP = {
        SHA_512 => 'SHA512'
      }

      endian  :little

      uint16 :hash_algorithm_count, label: 'Hash Algorithm Count', initial_value: -> { hash_algorithms.size }
      uint16 :salt_length,          label: 'Salt Length',          initial_value: -> { salt.num_bytes }
      array  :hash_algorithms,      label: 'Hash Algorithms',      type: :uint16, initial_length: -> { hash_algorithm_count }
      string :salt,                 label: 'Salt',                 read_length: -> { salt_length }
    end

    # An SMB2 ENCRYPTION_CAPABILITIES context struct as defined in
    # [2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/16693be7-2b27-4d3b-804b-f605bde5bcdd)
    class EncryptionCapabilities < BinData::Record
      AES_128_CCM = 0x0001
      AES_128_GCM = 0x0002
      AES_256_CCM = 0x0003
      AES_256_GCM = 0x0004
      ENCRYPTION_ALGORITHM_MAP = {
        AES_128_CCM => 'AES-128-CCM',
        AES_128_GCM => 'AES-128-GCM',
        AES_256_CCM => 'AES-256-CCM',
        AES_256_GCM => 'AES-256-GCM'
      }

      endian  :little

      uint16 :cipher_count, label: 'Cipher Count', initial_value: -> { ciphers.size }
      array  :ciphers,      label: 'Ciphers',      type: :uint16, initial_length: -> { cipher_count }
    end

    # An SMB2 COMPRESSION_CAPABILITIES context struct as defined in
    # [2.2.3.1.3 SMB2_COMPRESSION_CAPABILITIES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271)
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
      COMPRESSION_ALGORITHM_MAP = {
        NONE         => 'NONE',
        LZNT1        => 'LZNT1',
        LZ77         => 'LZ77',
        LZ77_Huffman => 'LZ77_Huffman',
        Pattern_V1   => 'Pattern_V1'
      }

      endian  :little

      uint16 :compression_algorithm_count, label: 'Compression Algorithm Count', initial_value: -> { compression_algorithms.size }
      uint16 :padding,                     label: 'Padding',                     initial_value: 0
      uint32 :flags,                       label: 'Flags'
      array  :compression_algorithms,      label: 'Compression Algorithms',      type: :uint16, initial_length: -> { compression_algorithm_count }
    end

    # An SMB2 NETNAME_NEGOTIATE_CONTEXT_ID context struct as defined in
    # [2.2.3.1.4 SMB2_NETNAME_NEGOTIATE_CONTEXT_ID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ca6726bd-b9cf-43d9-b0bc-d127d3c993b3)
    class NetnameNegotiateContextId < BinData::Record
      endian  :little

      count_bytes_remaining :bytes_remaining
      default_parameter data_length: nil
      hide :bytes_remaining

      string16 :net_name, label: 'Net Name', read_length: -> { data_length.nil? ? bytes_remaining : data_length }
    end

    # An SMB2 TRANSPORT_CAPABILITIES context struct as defined in
    # [2.2.3.1.5 SMB2_TRANSPORT_CAPABILITIES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/450a1888-a645-4988-8638-5a11f4617545)
    class TransportCapabilities < BinData::Record
      SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY = 1 # Transport security is offered to skip SMB2 encryption on this connection.

      endian :little

      uint32 :flags, label: 'Flags'
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
      # The NegotiateContext Data field contains the transport capabilities, as specified in section 2.2.3.1.5.
      SMB2_TRANSPORT_CAPABILITIES          = 0x0006

      endian  :little

      string :pad,          label: 'Padding',     length: -> { pad_length }
      uint16 :context_type, label: 'Context Type'
      uint16 :data_length,  label: 'Data Length', initial_value: -> { data.num_bytes }
      uint32 :reserved,     label: 'Reserved',    initial_value: 0
      choice :data,         label: 'Data',        selection: -> { context_type } do
        preauth_integrity_capabilities SMB2_PREAUTH_INTEGRITY_CAPABILITIES, label: 'Preauthentication Integrity Capabilities'
        encryption_capabilities        SMB2_ENCRYPTION_CAPABILITIES,        label: 'Encryption Capabilities'
        compression_capabilities       SMB2_COMPRESSION_CAPABILITIES,       label: 'Compression Capabilities'
        netname_negotiate_context_id   SMB2_NETNAME_NEGOTIATE_CONTEXT_ID,   label: 'Netname Negotiate Context ID', data_length: :data_length
        transport_capabilities         SMB2_TRANSPORT_CAPABILITIES,         label: 'Transport Capabilities'
      end

      def pad_length
        offset = pad.abs_offset % 8
        (8 - offset) % 8
      end

    end
  end
end
