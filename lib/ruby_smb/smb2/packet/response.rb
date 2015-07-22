require 'ruby_smb/smb2/packet'

# A response header, largely copy-pasta'd from the request header.
class RubySMB::Smb2::Packet::Response < RubySMB::Smb2::Packet::Generic

  def initialize(*args)
    super
    self.header_flags &= RubySMB::Smb2::Packet::HEADER_FLAGS[:RESPONSE]
  end

end
