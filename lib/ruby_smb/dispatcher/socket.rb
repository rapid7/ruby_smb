require 'socket'

# This class provides a wrapper around a Socket for the packet Dispatcher.
# It allows for dependency injection of different Socket implementations.
class RubySMB::Dispatcher::Socket < RubySMB::Dispatcher::Base
  # The underlying socket that we select on
  # @!attribute [rw] tcp_socket
  #   @return [IO]
  attr_accessor :tcp_socket

  # @param tcp_socket [IO]
  def initialize(tcp_socket)
    @tcp_socket = tcp_socket
    if @tcp_socket.respond_to?(:setsockopt)
      @tcp_socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
    end
  end

  # @param host [String] passed to TCPSocket.new
  # @param port [Fixnum] passed to TCPSocket.new
  def self.connect(host, port: 445, socket: TCPSocket.new(host, port))
    new(socket)
  end

  # @param packet [SMB2::Packet,#to_s]
  # @return [void]
  def send_packet(packet)
    data = nbss(packet) + packet.to_binary_s
    bytes_written = 0
    begin
      while bytes_written < data.size
        bytes_written += @tcp_socket.write(data[bytes_written..-1])
      end
    rescue IOError, Errno::ECONNABORTED, Errno::ECONNRESET => e
      raise RubySMB::Error::CommunicationError, "An error occured writing to the Socket: #{e.message}"
    end
    nil
  end

  # Read a packet off the wire and parse it into a string
  # Throw Error::NetBiosSessionService if there's an error reading the first 4 bytes,
  # which are assumed to be the NetBiosSessionService header.
  # @return [String]
  def recv_packet
    begin
      IO.select([@tcp_socket])
      nbss_header = @tcp_socket.read(4) # Length of NBSS header. TODO: remove to a constant
      if nbss_header.nil?
        raise ::RubySMB::Error::NetBiosSessionService, 'NBSS Header is missing'
      else
        length = nbss_header.unpack('N').first
      end
      IO.select([@tcp_socket])
      data = @tcp_socket.read(length)
      data << @tcp_socket.read(length - data.length) while data.length < length

      data
    rescue Errno::EINVAL, Errno::ECONNABORTED, Errno::ECONNRESET, TypeError, NoMethodError => e
      raise RubySMB::Error::CommunicationError, "An error occured reading from the Socket #{e.message}"
    end
  end
end
