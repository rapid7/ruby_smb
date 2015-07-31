RSpec.describe RubySMB::Dispatcher::Socket do
  let(:fake_tcp_socket){ StringIO.new("deadbeef") }

  subject(:smb_socket){ described_class.new(fake_tcp_socket) }

  # Don't try to actually select on our StringIO fake socket
  before(:each) do
    allow(IO).to receive(:select).and_return(nil)
  end

  describe "#connect" do
    it 'should support setting a custom socket object' do
      socket = described_class.connect("172.16.22.165", socket: fake_tcp_socket)
      expect(socket.tcp_socket).to eq(fake_tcp_socket)
    end
  end

  describe "#recv_packet" do
    let(:blank_socket){StringIO.new("")}

    describe "when reading from the socket results in a nil value" do
      it 'should raise Error::NetBiosSessionService' do
        smb_socket.tcp_socket = blank_socket
        expect{ smb_socket.recv_packet }.to raise_error(::RubySMB::Error::NetBiosSessionService)
      end
    end
  end
end