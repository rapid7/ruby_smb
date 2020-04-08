module RubySMB
  module SMB2
    module Packet
      # An SMB2 COMPRESSION_TRANSFORM_HEADER Packet as defined in
      # [2.2.42 SMB2 COMPRESSION_TRANSFORM_HEADER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1d435f21-9a21-4f4c-828e-624a176cf2a0)
      class CompressionTransformHeader < RubySMB::GenericPacket
        endian :little

        bit32            :protocol,                         label: 'Protocol ID Field',      initial_value: 0xFC534D42
        uint32           :original_compressed_segment_size, label: 'Original Compressed Segment Size'
        uint16           :compression_algorithm,            label: 'Compression Algorithm'
        uint16           :flags,                            label: 'Flags'
        uint32           :offset,                           label: 'Offset / Length'
      end

      # An SMB2 SMB2_COMPRESSION_TRANSFORM_HEADER_PAYLOAD Packet as defined in
      # [2.2.42.1 SMB2_COMPRESSION_TRANSFORM_HEADER_PAYLOAD](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8898e8e7-f1b2-47f5-a525-2ce5bad6db64)
      class Smb2CompressionPayloadHeader < RubySMB::GenericPacket
        endian :little
        hide   :reserved

        uint16           :algorithm_id,                     label: 'Algorithm ID'
        uint16           :reserved
        uint32           :payload_length,                   label: 'Compressed Payload Length'
      end

      # An SMB2 SMB2_COMPRESSION_PATTERN_PAYLOAD_V1 Packet as defined in
      # [2.2.42.2 SMB2_COMPRESSION_PATTERN_PAYLOAD_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f6859837-395a-4d0a-8971-1fc3919e2d09)
      class Smb2CompressionPatternPayloadV1 < RubySMB::GenericPacket
        endian :little
        hide   :reserved1, :reserved2

        uint8            :pattern,                          label: 'Pattern'
        uint8            :reserved1
        uint16           :reserved2
        uint32           :repetitions,                      label: 'Repetitions'
      end
    end
  end
end

