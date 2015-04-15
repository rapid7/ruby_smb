
class Smb2::File
  attr_accessor :client
  attr_accessor :create_response

  def initialize(client:, create_response:)
    self.client = client
    self.create_response = create_response
  end

end
