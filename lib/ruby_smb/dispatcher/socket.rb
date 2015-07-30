require 'socket'
# This class provides a wrapper around a Socket for the packet Dispatcher.
# It allows for dependency injection of different Socket implementations.
class RubySMB::Dispatcher::Socket < RubySMB::Dispatcher::Base

  # @!attribute [rw] socket
  #   @return [IO]
  attr_accessor :socket

  # @param socket [IO]
  def initialize(socket)
    @socket = socket
  end

  # @param host [String] passed to TCPSocket.new
  # @param port [Fixnum] passed to TCPSocket.new
  def self.connect(host, port=445)
    new(::TCPSocket.new(host, port))
  end

  # @param socket [IO]
  def initialize(socket)
    @socket = socket
  end

  # @param packet [SMB2::Packet,#to_s]
  # @return [void]
  def send_packet(packet)
    data = nbss(packet) + packet.to_s
    bytes_written = 0
    while bytes_written < data.size
      bytes_written += @socket.write(data[bytes_written..-1])
    end

    nil
  end

  # Read a packet off the wire and parse it into a string
  # Throw Error::NetBiosSessionService if there's an error reading the first 4 bytes,
  # which are assumed to be the NetBiosSessionService header.
  # @return [String]
  # @todo should return SMB2::Packet
  def recv_packet
    IO.select([@socket])
    nbss_header = @socket.read(4) # Length of NBSS header. TODO: remove to a constant
    if nbss_header.nil?
      raise ::RubySMB::Error::NetBiosSessionService, "NBSS Header is missing"
    else
      length = nbss_header.unpack("N").first
    end
    IO.select([@socket])
    data = @socket.read(length)
    while data.length < length
      data << @socket.read(length - data.length)
    end

    RubySMB::SMB2::Packet.parse(data)
  end

end
