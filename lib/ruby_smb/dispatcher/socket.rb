require 'socket'

class RubySMB::Dispatcher::Socket < Smb2::Dispatcher::Base

  # @!attribute [rw] socket
  #   @return [IO]
  attr_accessor :socket

  # @param host [String] passed to TCPSocket.new
  # @param port [Fixnum] passed to TCPSocket.new
  def self.connect(host, port=445)
    new(::TCPSocket.new(host, port))
  end

  # @param socket [IO]
  def initialize(socket)
    @socket = socket
  end

  # @param packet [Smb2::Packet,#to_s]
  # @return [void]
  def send_packet(packet)
    data = nbss(packet) + packet.to_s
    bytes_written = 0
    while bytes_written < data.size
      bytes_written += @socket.write(data[bytes_written..-1])
    end

    nil
  end

  # @return [String]
  # @todo should return Smb2::Packet
  def recv_packet
    IO.select([@socket])
    nbss_header = @socket.read(4)
    if nbss_header.nil?
      raise "omg"
    else
      length = nbss_header.unpack("N").first
    end
    IO.select([@socket])
    data = @socket.read(length)
    while data.length < length
      data << @socket.read(length - data.length)
    end

    Smb2::Packet.parse(data)
  end

end
