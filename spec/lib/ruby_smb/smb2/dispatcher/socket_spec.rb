RSpec.describe RubySMB::Dispatcher::Socket do
  subject(:smb_socket){ described_class.new(StringIO.new("deadbeef")) }

  # Don't try to actually select on our StringIO fake socket
  before(:each) do
    allow(IO).to receive(:select).and_return(nil)
  end

  describe "#connect" do
    it 'should support setting a custom socket' 
  end

  describe "#recv_packet" do

    let(:blank_socket){StringIO.new("")}
    describe "when reading from the socket results in a nil value" do
      it 'should raise Error::NetBiosSessionService' do
        smb_socket.socket = blank_socket
        expect(smb_socket.recv_packet).to raise_error(::RubySMB::Error::NetBiosSessionService)
      end
    end
  end
end