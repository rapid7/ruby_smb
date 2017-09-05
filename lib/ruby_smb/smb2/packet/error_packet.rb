module RubySMB
  module SMB2
    module Packet
      # An SMB2 Error packet for when an incomplete response comes back
      class ErrorPacket < RubySMB::GenericPacket
        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 4
        uint8        :error_data
      end
    end
  end
end
