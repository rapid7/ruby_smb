module RubySMB
  module SMB1
    module Packet

      # This packet represent an SMB1 Response Packet when the parameter and
      # data blocks will be empty.
      class EmptyPacket < RubySMB::GenericPacket
        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block
      end
    end
  end
end