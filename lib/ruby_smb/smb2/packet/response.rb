require 'ruby_smb/smb2/packet'

# A response header, largely copy-pasta'd from the request header.
class RubySMB::SMB2::Packet::Response < RubySMB::SMB2::Packet::Generic

  def initialize(*args)
    super
    self.header_flags &= RubySMB::SMB2::Packet::HEADER_FLAGS[:RESPONSE]
  end

end
