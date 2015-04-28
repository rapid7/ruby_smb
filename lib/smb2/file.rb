
require 'smb2/packet/query/standard_information'

# An open file on the remote filesystem.
class Smb2::File

  # The tree that {Tree#create created} this File
  #
  # @return [Smb2::Tree]
  attr_accessor :tree

  # The server's response from when we {Tree#create created} this File
  #
  # @return [Smb2::Packet::CreateResponse]
  attr_accessor :create_response

  # The last response we got from {#read}. Useful for figuring out what went
  # wrong.
  #
  # @return [Smb2::Packet::ReadResponse]
  attr_accessor :last_read_response

  # @param tree [Smb2::Tree] the Tree where this File was opened. See {#tree}
  # @param create_response [Smb2::Packet::CreateResponse] the server's
  #   response from when we {Tree#create created} this File. See
  #   {#create_response}
  def initialize(tree:, create_response:)
    self.tree = tree
    self.create_response = create_response
  end


  # Close this File handle on the server
  #
  # @return [Smb2::Packet::CloseResponse]
  def close
    packet = Smb2::Packet::CloseRequest.new(
      file_id: self.create_response.file_id
    )

    response = tree.send_recv(packet)

    Smb2::Packet::CloseResponse.new(response)
  end

  # @return [String]
  def inspect
    "#<Smb2::File file-id=#{create_response.file_id.unpack("H*").first} >"
  end

  # Call {#read_chunk} repeatedly until we get everything
  #
  # @note Beware of ballooning memory usage
  # @note Calling this on a pipe without a `length` is probably a really bad
  #   idea
  #
  # @param offset [Fixnum] offset from the beginning of the file (*default*: 0)
  # @param length [Fixnum,nil] number of bytes to read. If this is nil, read
  #   the whole file, i.e. {#size} bytes.
  # @return [String] full contents of the remote file
  def read(length = nil, offset: 0)
    data = ''
    max = tree.client.max_read_size
    length ||= size - offset

    # Starting from `offset`, up to `length` bytes after `offset`, counting by
    # maximum chunk size
    (offset...(offset+length)).step(max) do |step|
      # when we are close to the end, we need to read fewer then max bytes
      len = [ max, length - data.length ].min
      data << read_chunk(offset: step, length: len)
    end

    data
  end

  # Send a {Smb2::Packet::ReadRequest ReadRequest} and return the data.
  #
  # @note Does not handle files being too large for a single request. See
  #   {#read} if `length` is greater than {Smb2::Client#max_read_size
  #   tree.client.max_read_size}
  #
  # @param offset [Fixnum] offset from the beginning of the file (*default*: 0)
  # @param length [Fixnum] number of bytes to read, starting from `offset`. If
  #   this is greater than the server's maximum read size, the server will
  #   respond with STATUS_INVALID_PARAMETER
  # @return [String]
  def read_chunk(offset: 0, length: self.tree.client.max_read_size)
    packet = Smb2::Packet::ReadRequest.new(
      read_offset: offset,
      read_length: length,
      file_id: self.create_response.file_id,
      minimum_count: 0
    )

    response = tree.send_recv(packet)

    response_packet = Smb2::Packet::ReadResponse.new(response)
    @last_read_response = response_packet

    response_packet.data
  end

  # The size of the file in bytes
  #
  # @return [Fixnum]
  def size
    packet = Smb2::Packet::QueryInfoRequest.new(
      info_type: Smb2::Packet::QUERY_INFO_TYPES[:FILE],
      file_info_class: Smb2::Packet::FILE_INFORMATION_CLASSES[:FileStandardInformation],
      output_buffer_length: 40,
      input_buffer_length: 0,
      file_id: self.create_response.file_id
    )
    response = tree.send_recv(packet)
    query_response = Smb2::Packet::QueryInfoResponse.new(response)
    info = Smb2::Packet::Query::StandardInformation.new(query_response.output_buffer)

    info.end_of_file
  end

  # Write the entire contents of `data`, starting at `offset` from the
  # beginning of the file.
  #
  # @param data [String] what to write
  # @param offset [Fixnum] where in the file to start writing
  # @return [void]
  def write(data, offset: 0)
    max = tree.client.max_write_size
    (offset...data.length).step(max) do |step|
      packet = Smb2::Packet::WriteRequest.new(
        file_offset: step,
        file_id: self.create_response.file_id,
        data: data.slice(step, max)
      )
      response = tree.send_recv(packet)

      response_packet = Smb2::Packet::WriteResponse.new(response)

      response_packet
    end

    self
  end

end
