
# A connected tree, as returned by a {Smb2::Packet::TreeConnectRequest}.
class Smb2::Tree

  # The {Smb2::Client} on which this Tree is connected.
  #
  # @return [Smb2::Client]
  attr_accessor :client

  # The name of the share this Tree operates on
  #
  # @return [String]
  attr_accessor :share

  # The response that occasioned the creation of this {Tree}.
  #
  # @return [Smb2::Packet::TreeConnectResponse]
  attr_accessor :tree_connect_response

  # @param client [Smb::Client] (see {#client})
  # @param share [String] (see {#share})
  # @param tree_connect_response [Smb::Packet::TreeConnectResponse]
  def initialize(client:, share:, tree_connect_response:)
    unless tree_connect_response.is_a?(Smb2::Packet::TreeConnectResponse)
      raise TypeError, "tree_connect_response must be a TreeConnectResponse"
    end

    self.client = client
    self.share = share
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
  # @return [Smb2::File] if no block given
  # @return [Object] value of the block if block given
  def create(filename, mode = "r+")
    desired_access = desired_access_from_mode(mode)
    create_options = Smb2::Packet::CREATE_OPTIONS[:FILE_NON_DIRECTORY_FILE]
    share_access =
      Smb2::Packet::SHARE_ACCESS[:FILE_SHARE_READ] |
      Smb2::Packet::SHARE_ACCESS[:FILE_SHARE_WRITE]

    packet = Smb2::Packet::CreateRequest.new(
      create_options: create_options,
      desired_access: desired_access,
      disposition: disposition_from_file_mode(mode),
      filename: filename.encode("utf-16le"),
      impersonation: Smb2::Packet::IMPERSONATION_LEVELS[:IMPERSONATION],
      share_access: share_access,
    )

    response = send_recv(packet)

    create_response = Smb2::Packet::CreateResponse.new(response)
    file = Smb2::File.new(filename: filename, tree: self, create_response: create_response)
    if mode.start_with?("a")
      file.seek(create_response.end_of_file)
    end

    if block_given?
      value = yield file
      file.close
      value
    else
      file
    end
  end

  # Remove `filename` on the remote share.
  #
  # @example
  #   tree = client.tree_connect("\\\\192.168.99.134\\Share")
  #   tree.delete("path\\to\\remove_me.txt")
  #
  # @param filename [String] path to the file to be removed
  # @return [void]
  def delete(filename)
    share_access =
      Smb2::Packet::SHARE_ACCESS[:FILE_SHARE_READ] |
      Smb2::Packet::SHARE_ACCESS[:FILE_SHARE_WRITE] |
      Smb2::Packet::SHARE_ACCESS[:FILE_SHARE_DELETE]

    packet = Smb2::Packet::CreateRequest.new(
      create_options: Smb2::Packet::CREATE_OPTIONS[:FILE_DELETE_ON_CLOSE],
      desired_access: Smb2::Packet::FILE_ACCESS_MASK[:DELETE],
      disposition: Smb2::Packet::CREATE_DISPOSITIONS[:FILE_OPEN],
      filename: filename.encode("utf-16le"),
      impersonation: Smb2::Packet::IMPERSONATION_LEVELS[:IMPERSONATION],
      share_access: share_access,
    )

    response = send_recv(packet)

    create_response = Smb2::Packet::CreateResponse.new(response)
    file = Smb2::File.new(
      filename: filename,
      tree: self,
      create_response: create_response
    )
    file.close
  end

  # @return [String]
  def inspect
    if tree_connect_response.nt_status != 0
      stuff = "Error: #{tree_connect_response.nt_status.to_s 16}"
    else
      stuff = share
    end
    "#<#{self.class} #{stuff} >"
  end

  # Send a packet and return the response
  #
  # @param request [Smb2::Packet]
  # @return (see Client#send_recv)
  def send_recv(request)
    request.tree_id = self.tree_connect_response.tree_id
    request.process_id = 0

    client.send_recv(request)
  end

  private

  def desired_access_from_mode(mode)
    case mode
    when "r+", "w+", "a+", "w", "a"
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
    case mode
    when "r", "r+"
      Smb2::Packet::CREATE_DISPOSITIONS[:FILE_OPEN]
    when "w", "w+"
      # truncate
      Smb2::Packet::CREATE_DISPOSITIONS[:FILE_OVERWRITE_IF]
    when "a", "a+"
      Smb2::Packet::CREATE_DISPOSITIONS[:FILE_OPEN_IF]
    else
      raise ArgumentError
    end
  end

end
