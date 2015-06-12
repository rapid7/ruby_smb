#
module Smb2::Packet::Query
  autoload :StandardInformation, 'smb2/packet/query/standard_information'
  autoload :NamesInformation, 'smb2/packet/query/names_information'

  # Number of bytes in a StandardInformation packet.
  STANDARD_INFORMATION_SIZE = 40
end
