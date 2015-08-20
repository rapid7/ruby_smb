module RubySMB
module SMB1
# This module holds the namespace for all SMB1 packets and related structures.
class Packet
  def compose
    # implies transmit
    # build packet container
    # fill with SMB_Packet we want to send
  end

  def decompose
    # implies receive
    # build packet container
    # fill with SMB_Packet we expect to receive
  end
end
end
end
