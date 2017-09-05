RSpec.describe RubySMB::Dispatcher::Socket do
  class FakeSocket < StringIO
    def setsockopt(*args); end
  end

  let(:fake_tcp_socket) {
    FakeSocket.new('deadbeef')
  }

  subject(:smb_socket) { described_class.new(fake_tcp_socket) }
  let(:negotiate_response) { RubySMB::SMB2::Packet::NegotiateResponse.new }
  let(:nbss) { smb_socket.nbss(negotiate_response) }
  let(:response_packet) { nbss + negotiate_response.to_binary_s }

  # Don't try to actually select on our StringIO fake socket
  before(:each) do
    allow(IO).to receive(:select).and_return(nil)
  end

  it 'should attempt to set KEEPALIVE on the socket' do
    expect(fake_tcp_socket).to receive(:setsockopt).with(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
    described_class.new(fake_tcp_socket)
  end

  describe '#connect' do
    it 'should support setting a custom socket object' do
      socket = described_class.connect('172.16.22.165', socket: fake_tcp_socket)
      expect(socket.tcp_socket).to eq(fake_tcp_socket)
    end

    it 'should default to setting up a TCPSocket' do
      host = '172.16.22.165'
      port = 445
      expect(TCPSocket).to receive(:new).with(host, port)
      described_class.connect(host)
    end
  end

  describe '#recv_packet' do
    let(:blank_socket) { StringIO.new('') }
    let(:response_socket) { StringIO.new(response_packet) }

    describe 'when reading from the socket results in a nil value' do
      it 'should raise Error::NetBiosSessionService' do
        smb_socket.tcp_socket = blank_socket
        expect { smb_socket.recv_packet }.to raise_error(::RubySMB::Error::NetBiosSessionService)
      end
    end

    describe 'when reading an SMB Response packet' do
      it 'reads a number of bytes defined in the nbss header' do
        smb_socket.tcp_socket = response_socket
        expect(response_socket).to receive(:read).with(4).and_call_original
        expect(response_socket).to receive(:read).with(negotiate_response.do_num_bytes).and_call_original
        smb_socket.recv_packet
      end
    end

    it 'raises a CommunicationError if it encounters a socket error' do
      expect(fake_tcp_socket).to receive(:read).and_raise(Errno::ECONNRESET)
      expect { smb_socket.recv_packet }.to raise_error(RubySMB::Error::CommunicationError)
    end
  end

  describe '#send_packet' do
    it 'calls nbss to create the nbss header for the packet' do
      expect(smb_socket).to receive(:nbss).with(negotiate_response).and_return(nbss)
      smb_socket.send_packet(negotiate_response)
    end

    it 'writes the packet to the socket' do
      expect(fake_tcp_socket).to receive(:write).with(response_packet).and_call_original
      smb_socket.send_packet(negotiate_response)
    end

    it 'raises a CommunicationError if it encounters a socket error' do
      expect(fake_tcp_socket).to receive(:write).and_raise(Errno::ECONNRESET)
      expect { smb_socket.send_packet(negotiate_response) }.to raise_error(RubySMB::Error::CommunicationError)
    end
  end
end
