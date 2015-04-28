
# A connected tree, as returned by a {Smb2::Packet::TreeConnectRequest}.
class Smb2::Tree

  # The {Smb2::Client} to which this Tree is connected.
  #
  # @return [Smb2::Client]
  attr_accessor :client

  # The share
  #
  # @return [String]
  attr_accessor :tree

  # The response that occasioned the creation of this {Tree}.
  #
  # @return [Smb2::Packet::TreeConnectResponse]
  attr_accessor :tree_connect_response

  # @param client [Smb::Client]
  # @param tree_connect_response [Smb::Packet::TreeConnectResponse]
  def initialize(client:, tree:, tree_connect_response:)
    unless tree_connect_response.is_a?(Smb2::Packet::TreeConnectResponse)
      raise TypeError, "tree_connect_response must be a TreeConnectResponse"
    end

    self.client = client
    self.tree = tree
    self.tree_connect_response = tree_connect_response
  end

  # Open a file handle
  #
  # The protocol is persnickety about format. The `filename` must not begin
  # with a backslash or it will return a STATUS_INVALID_PARAMETER.
  #
  # If the optional code block is given, it will be passed the opened file as
  # an argument and the {File} object will automatically be {File#close
  # closed} when the block terminates. The value of the block will be
  # returned.
  #
  # @param filename [String,#encode] this will be encoded in utf-16le
  # @param mode [String] See stdlib ::File#mode
  # @yield [Smb2::File]
  # @return [Smb2::File]
  def create(filename, mode = "r+")
    desired_access = desired_access_from_mode(mode)
    create_options = Smb2::Packet::CREATE_OPTIONS[:FILE_NON_DIRECTORY_FILE]

    packet = Smb2::Packet::CreateRequest.new(
      filename: filename.encode("utf-16le"),
      desired_access: desired_access,
      impersonation: 2,
      share_access: 3,  # SHARE_WRITE | SHARE_READ
      disposition: disposition_from_file_mode(mode),
      create_options: create_options
    )

    response = send_recv(packet)

    create_response = Smb2::Packet::CreateResponse.new(response)
    file = Smb2::File.new(tree: self, create_response: create_response)

    if block_given?
      value = yield file
      file.close
      value
    else
      file
    end
  end

  def delete(filename)
    packet = Smb2::Packet::CreateRequest.new(
      filename: filename.encode("utf-16le"),
      desired_access: Smb2::Packet::FILE_ACCESS_MASK[:FILE_DELETE],
      impersonation: 2,
      share_access: 7, # SHARE_DELETE | SHARE_WRITE | SHARE_READ
      disposition: Smb2::Packet::CREATE_DISPOSITIONS[:FILE_OPEN],
      create_options: Smb2::Packet::CREATE_OPTIONS[:FILE_DELETE_ON_CLOSE]
    )

    response = send_recv(packet)

    Smb2::Packet::CreateResponse.new(response)
  end

  # @return [String]
  def inspect
    if tree_connect_response.header.nt_status != 0
      stuff = "Error: #{tree_connect_response.header.nt_status.to_s 16}"
    else
      stuff = tree
    end
    "#<#{self.class} #{stuff} >"
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

  def desired_access_from_mode(mode)
    case mode
    when "r+","w+","a+","w","a"
      # read/write and write-only. Samba's smbclient sets all the read flags
      # when writing, so emulate that.
      Smb2::Packet::FILE_ACCESS_MASK[:FILE_READ_DATA] |
        Smb2::Packet::FILE_ACCESS_MASK[:FILE_WRITE_DATA] |
        Smb2::Packet::FILE_ACCESS_MASK[:FILE_APPEND_DATA] |
        Smb2::Packet::FILE_ACCESS_MASK[:FILE_READ_EA] |
        Smb2::Packet::FILE_ACCESS_MASK[:FILE_WRITE_EA] |
        Smb2::Packet::FILE_ACCESS_MASK[:FILE_READ_ATTRIBUTES] |
        Smb2::Packet::FILE_ACCESS_MASK[:FILE_WRITE_ATTRIBUTES] |
        Smb2::Packet::FILE_ACCESS_MASK[:READ_CONTROL] |
        Smb2::Packet::FILE_ACCESS_MASK[:SYNCHRONIZE]
    when "r"
      # read-only
      Smb2::Packet::FILE_ACCESS_MASK[:FILE_READ_DATA] |
        Smb2::Packet::FILE_ACCESS_MASK[:FILE_READ_EA] |
        Smb2::Packet::FILE_ACCESS_MASK[:FILE_READ_ATTRIBUTES] |
        Smb2::Packet::FILE_ACCESS_MASK[:READ_CONTROL] |
        Smb2::Packet::FILE_ACCESS_MASK[:SYNCHRONIZE]
    else
      raise ArgumentError
    end
  end

  def disposition_from_file_mode(mode)
    case mode[0]
    when "r","r+"
      Smb2::Packet::CREATE_DISPOSITIONS[:FILE_OPEN]
    when "w","w+"
      # truncate
      Smb2::Packet::CREATE_DISPOSITIONS[:FILE_OVERWRITE_IF]
    when "a","a+"
      Smb2::Packet::CREATE_DISPOSITIONS[:FILE_CREATE]
    else
      raise ArgumentError
    end
  end

end
