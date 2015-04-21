
# A connected tree, as returned by a {Smb2::Packet::TreeConnectRequest}.
class Smb2::Tree

  # The {Smb2::Client} to which this Tree is connected.
  #
  # @return [Smb2::Client]
  attr_accessor :client

  # The response that occasioned the creation of this {Tree}.
  #
  # @return [Smb2::Packet::TreeConnectResponse]
  attr_accessor :tree_connect_response

  # @param client [Smb::Client]
  # @param tree_connect_response [Smb::Packet::TreeConnectResponse]
  def initialize(client:, tree_connect_response:)
    unless tree_connect_response.is_a?(Smb2::Packet::TreeConnectResponse)
      raise TypeError, "tree_connect_response must be a TreeConnectResponse"
    end

    self.client = client
    self.tree_connect_response = tree_connect_response
  end

  # Open a file handle
  #
  # The protocol is persnickety about format. The `filename` must not begin
  # with a backslash or it will return a STATUS_INVALID_PARAMETER.
  #
  # @param filename [String,#encode] this will be encoded in utf-16le
  # @return [Smb2::File]
  def create(filename, mode: "r")
    desired_access = Smb2::Packet::FILE_ACCESS_MASK[:MAXIMUM_ALLOWED] # YOLO
    create_options = Smb2::Packet::CREATE_OPTIONS[:FILE_NON_DIRECTORY_FILE]

    packet = Smb2::Packet::CreateRequest.new do |request|
      request.filename = filename.encode("utf-16le")
      # @todo document all these flags. value copied from smbclient traffic
      request.desired_access = desired_access
      request.impersonation = 2
      request.share_access = 3  # SHARE_WRITE | SHARE_READ
      request.disposition = disposition_from_file_mode(mode)
      request.create_options = create_options
    end

    response = send_recv(packet)

    create_response = Smb2::Packet::CreateResponse.new(response)
    Smb2::File.new(tree: self, create_response: create_response)
  end

  # Send a packet and return the response
  #
  # @param request [Smb2::Packet]
  # @return (see Client#send_recv)
  def send_recv(request)
    header = request.header
    header.tree_id = self.tree_connect_response.header.tree_id
    header.process_id = 0
    request.header = header

    client.send_recv(request)
  end


  private


  def disposition_from_file_mode(mode)
    case mode
    when "r"
      Smb2::Packet::CREATE_DISPOSITIONS[:FILE_OPEN]
    when "w"
      Smb2::Packet::CREATE_DISPOSITIONS[:FILE_SUPERSEDE]
    when "a"
      Smb2::Packet::CREATE_DISPOSITIONS[:FILE_CREATE]
    end
  end

end
