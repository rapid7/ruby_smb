
require 'smb2/packet/query/standard_information'

# An open file on the remote filesystem.
class Smb2::File

  # Some day we'll document all of these in one place
  STATUS_END_OF_FILE = 0xC0000011

  # The server's response from when we {Tree#create created} this File
  #
  # @return [Smb2::Packet::CreateResponse]
  attr_accessor :create_response

  # @return [String]
  attr_accessor :filename

  # The last response we got from {#read}. Useful for figuring out what went
  # wrong.
  #
  # @return [Smb2::Packet::ReadResponse]
  attr_accessor :last_read_response

  # Current offset of the read/write pointer from the beginning of the file,
  # in bytes.
  #
  # @return [Fixnum]
  attr_accessor :pos

  # The tree that {Tree#create created} this File
  #
  # @return [Smb2::Tree]
  attr_accessor :tree

  # @param tree [Smb2::Tree] the Tree where this File was opened. See {#tree}
  # @param create_response [Smb2::Packet::CreateResponse] the server's
  #   response from when we {Tree#create created} this File. See
  #   {#create_response}
  def initialize(filename:, tree:, create_response:)
    self.filename = filename
    self.tree = tree
    self.create_response = create_response
    self.pos = 0
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

  # Whether the current read/write pointer is at the end of the file
  #
  # @return [Boolean]
  def eof?
    (@last_read_response && @last_read_response.header.nt_status == STATUS_END_OF_FILE) || pos == size
  end

  # @return [String]
  def inspect
    "#<Smb2::File:#{filename} file-id=#{create_response.file_id.unpack("H*").first} >"
  end

  # Call {#read_chunk} repeatedly until we get `length` bytes or hit eof.
  #
  # @note Beware of ballooning memory usage
  # @note Calling this on a pipe without a `length` is probably a really bad
  #   idea
  #
  # @param offset [Fixnum] offset from the beginning of the file (*default*: 0)
  # @param length [Fixnum,nil] number of bytes to read. If this is nil, read
  #   the whole file, i.e. {#size} bytes.
  # @return [String] full contents of the remote file
  def read(length = nil, offset: self.pos)
    data = ''
    max = tree.client.max_read_size
    length ||= size - offset
    seek(offset)

    while data.length < length && !eof?
      # when we are close to the end, we need to read fewer then max bytes
      len = [ max, length - data.length ].min
      data << read_chunk(offset: pos, length: len)
    end

    data
  end

  # Send a single {Smb2::Packet::ReadRequest ReadRequest} and return the data.
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
  def read_chunk(offset: self.pos, length: self.tree.client.max_read_size)
    packet = Smb2::Packet::ReadRequest.new(
      read_offset: offset,
      read_length: length,
      file_id: self.create_response.file_id,
      minimum_count: 0
    )

    response = tree.send_recv(packet)

    response_packet = Smb2::Packet::ReadResponse.new(response)
    @last_read_response = response_packet

    seek(response_packet.data_length, IO::SEEK_CUR)

    response_packet.data
  end

  # Seeks to a given `offset` in the stream according to the value of
  # `whence`:
  #
  # |`whence`||
  # |----------------------|--------------------------------------------------
  # | :CUR or IO::SEEK_CUR | Seeks to `amount` plus current position
  # | :END or IO::SEEK_END | Seeks to `amount` plus end of stream (you probably want a negative value for `amount`)
  # | :SET or IO::SEEK_SET | Seeks to the absolute location given by `amount`
  #
  # @see http://ruby-doc.org/core-2.2.2/IO.html#method-i-seek
  # @param amount [Fixnum]
  # @param whence [Symbol]
  def seek(amount, whence=IO::SEEK_SET)
    @pos = case whence
           when :CUR, IO::SEEK_CUR
             @pos + amount
           when :END, IO::SEEK_END
             amount + size
           when :SET, IO::SEEK_SET
             amount
           end
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
  def write(data, offset: self.pos)
    max = tree.client.max_write_size
    bytes_written = 0
    seek(offset)

    while data.length > bytes_written
      packet = Smb2::Packet::WriteRequest.new(
        file_offset: pos,
        file_id: self.create_response.file_id,
      )
      packet.data = data.slice(bytes_written, max)

      response = tree.send_recv(packet)

      response_packet = Smb2::Packet::WriteResponse.new(response)
      # @todo raise instead?
      break if response_packet.header.nt_status != 0

      bytes_written += response_packet.byte_count
      seek(bytes_written)
    end

    bytes_written
  end

end
