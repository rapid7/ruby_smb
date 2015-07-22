require 'ruby_smb/smb2/packet'

# A response header, largely copy-pasta'd from the request header.
class Smb2::Packet::Response < Smb2::Packet::Generic

  def initialize(*args)
    super
    self.header_flags &= Smb2::Packet::HEADER_FLAGS[:RESPONSE]
  end

end
