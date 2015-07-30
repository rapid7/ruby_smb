
# An open file on the remote filesystem.
class RubySMB::SMB2::File

  # The server's response from when we {Tree#create created} this File
  #
  # @return [RubySMB::SMB2::Packet::CreateResponse]
  attr_accessor :create_response

  # Path to the remote file.
  #
  # A UNC path like this:
  #
  #   \\hostname-or-ip\share\path\to\file.txt
  #
  # gets broken up like this:
  #
  #   tree.share -> \\hostname-or-ip\share
  #   file.filename -> path\to\file.txt
  #
  # Note that share has no trailing backslash and filename has no prefixed
  # backslash.
  #
  # @return [String]
  attr_accessor :filename

  # The last response we got from {#read}. Useful for figuring out what went
  # wrong.
  #
  # @return [RubySMB::SMB2::Packet::ReadResponse]
  attr_accessor :last_read_response

  # Current offset of the read/write pointer from the beginning of the file,
  # in bytes.
  #
  # @return [Fixnum]
  attr_accessor :pos
  alias tell pos

  # The tree that {Tree#create created} this File
  #
  # @return [RubySMB::SMB2::Tree]
  attr_accessor :tree

  # @param tree [RubySMB::SMB2::Tree] the Tree where this File was opened. See {#tree}
  # @param filename [String] remote filesystem path of this File.
  # @param create_response [RubySMB::SMB2::Packet::CreateResponse] the server's
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
  # @return [RubySMB::SMB2::Packet::CloseResponse]
  def close
    packet = RubySMB::SMB2::Packet::CloseRequest.new(
      file_id: self.create_response.file_id
    )

    response = tree.send_recv(packet)

    RubySMB::SMB2::Packet::CloseResponse.new(response)
  end

  # Whether the current read/write pointer is at the end of the file
  #
  # @return [Boolean]
  def eof?
    (last_read_response && last_read_response.nt_status == WindowsError::NTStatus::STATUS_END_OF_FILE) || pos == size
  end

  # @return [String]
  def inspect
    "#<SMB2::File:#{tree.share}\\#{filename} file-id=#{create_response.file_id.unpack("H*").first} >"
  end

  # Call {#read_chunk} repeatedly until we get `length` bytes or hit {#eof?
  # end of file}.
  #
  # @note Beware of ballooning memory usage
  # @note Calling this on a pipe without a `length` is probably a really bad
  #   idea
  #
  # @param length [Fixnum,nil] number of bytes to read. If this is nil, read
  #   the whole file, i.e. {#size} bytes.
  # @return [String] full contents of the remote file
  def read(length = nil)
    data = ''
    max = tree.client.max_read_size
    length ||= size

    while data.length < length && !eof?
      # when we are close to the end, we need to read fewer then max bytes
      len = [max, length - data.length].min
      response_packet = read_chunk(offset: pos, length: len)
      data << response_packet.data
    end

    data
  end

  # Send a single {SMB2::Packet::ReadRequest ReadRequest} and return the data.
  #
  # @note Does not handle files being too large for a single request. See
  #   {#read} if `length` is greater than {SMB2::Client#max_read_size
  #   tree.client.max_read_size}
  #
  # @param offset [Fixnum] offset from the beginning of the file (*default*: 0)
  # @param length [Fixnum] number of bytes to read, starting from `offset`. If
  #   this is greater than the server's maximum read size, the server will
  #   respond with STATUS_INVALID_PARAMETER
  # @return [RubySMB::SMB2::Packet::ReadResponse]
  def read_chunk(offset: self.pos, length: self.tree.client.max_read_size)
    packet = RubySMB::SMB2::Packet::ReadRequest.new(
      read_offset: offset,
      read_length: length,
      file_id: self.create_response.file_id,
      minimum_count: 0
    )

    response = tree.send_recv(packet)

    response_packet = RubySMB::SMB2::Packet::ReadResponse.new(response)
    self.last_read_response = response_packet

    seek(response_packet.data_length, IO::SEEK_CUR)

    response_packet
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
  # @see http://ruby-doc.org/core-2.2.2/IO.html#SEEK_CUR
  # @see http://ruby-doc.org/core-2.2.2/IO.html#SEEK_END
  # @see http://ruby-doc.org/core-2.2.2/IO.html#SEEK_SET
  # @param amount [Fixnum]
  # @param whence [Symbol]
  # @return [Integer] Always 0 to match the {http://ruby-doc.org/core-2.2.2/IO.html#method-i-seek IO#seek} API
  def seek(amount, whence = IO::SEEK_SET)
    self.pos = case whence
               when :CUR, IO::SEEK_CUR
                 pos + amount
               when :END, IO::SEEK_END
                 amount + size
               when :SET, IO::SEEK_SET
                 amount
               end
    0
  end

  # The size of the file in bytes
  #
  # @return [Fixnum]
  def size
    packet = RubySMB::SMB2::Packet::QueryInfoRequest.new(
      info_type: RubySMB::SMB2::Packet::QUERY_INFO_TYPES[:FILE],
      file_info_class: RubySMB::SMB2::Packet::FILE_INFORMATION_CLASSES[:FileStandardInformation],
      output_buffer_length: RubySMB::SMB2::Packet::Query::STANDARD_INFORMATION_SIZE,
      input_buffer_length: 0,
      file_id: self.create_response.file_id
    )
    response = tree.send_recv(packet)
    query_response = RubySMB::SMB2::Packet::QueryInfoResponse.new(response)
    info = RubySMB::SMB2::Packet::Query::StandardInformation.new(query_response.output_buffer)

    info.end_of_file
  end

  # Write the entire contents of `data`, starting at `offset` bytes from the
  # beginning of the file.
  #
  # @param data [String] what to write
  # @param offset [Fixnum] where in the file to start writing
  # @return [Fixnum] number of bytes written. This may be less than the length
  #   of `data` if there was an error.
  def write(data, offset: self.pos)
    max = tree.client.max_write_size
    bytes_written = 0
    seek(offset)

    while data.length > bytes_written
      data_chunk = data.slice(bytes_written, max)
      response_packet = write_chunk(data_chunk, offset: pos)

      # @todo raise instead?
      break if response_packet.nt_status != WindowsError::NTStatus::STATUS_SUCCESS

      bytes_written += response_packet.byte_count
      seek(offset + bytes_written)
    end

    bytes_written
  end

  # Write a single chunk of data.
  #
  # @note Does not handle data being too large for a single request. See
  #   {#write} if `data` is larger than {SMB2::Client#max_write_size
  #   tree.client.max_write_size}
  #
  # @param data [String] what to write
  # @param offset [Fixnum] where in the file to start writing
  # @return [RubySMB::SMB2::Packet::WriteResponse]
  def write_chunk(data, offset: self.pos)
    packet = RubySMB::SMB2::Packet::WriteRequest.new(
      file_offset: offset,
      file_id: self.create_response.file_id,
      data: data
    )

    response = tree.send_recv(packet)

    RubySMB::SMB2::Packet::WriteResponse.new(response)
  end

end
