RSpec.describe RubySMB::SMB2::Pipe do

  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }

  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:tree_id) { 2049 }
  let(:path) { '\\192.168.1.1\IPC$' }
  let(:connect_response) {
    packet = RubySMB::SMB2::Packet::TreeConnectResponse.new
    packet.smb2_header.tree_id = tree_id
    packet.maximal_access.read("\xff\x01\x1f\x00")
    packet.share_type = 0x01
    packet
  }

  let(:tree) { RubySMB::SMB2::Tree.new(client: client, share: path, response: connect_response) }
  let(:file_id) { RubySMB::Field::Smb2Fileid.read('\x6d\x01\x00\x00\x00\x00\x00\x00\x\x01\x00\x00\x00\xff\xff\xff\xff') }
  let(:time) { DateTime.now }
  let(:create_response) {
    RubySMB::SMB2::Packet::CreateResponse.new(
      file_id: file_id,
      end_of_file: 108,
      allocation_size: 112,
      last_access: time,
      last_change: time,
      last_write: time
    )
  }

  let(:ioctl_response) {
    packet = RubySMB::SMB2::Packet::IoctlResponse.new
    packet.buffer = "\x03\x00\x00\x00" + "\x10\x20\x30\x40" + "\x00\x00\x00\x00" + "\x00\x00\x00\x00"
    packet
  }

  subject(:pipe) { described_class.new(name: 'msf-pipe', response: create_response, tree: tree) }

  describe '#peek_available' do
    it 'reads the correct number of bytes available' do
      allow(pipe).to receive(:peek) { ioctl_response }
      allow(pipe).to receive(:peek_available) { pipe.peek.buffer.unpack('VV')[1] }
      expect(pipe.peek_available).to eq(0x40302010)
    end
  end
  
  describe '#peek_state' do
    it 'reads the correct state of the pipe' do
      allow(pipe).to receive(:peek) { ioctl_response }
      allow(pipe).to receive(:peek_state)  { pipe.peek.buffer.unpack('V')[0] }
      expect(pipe.peek_state).to eq(RubySMB::SMB2::Pipe::STATUS_CONNECTED)
    end
  end

  describe '#is_connected?' do
    it 'identifies that the pipe is connected from the status' do
      allow(pipe).to receive(:peek) { ioctl_response }
      allow(pipe).to receive(:peek_state)  { pipe.peek.buffer.unpack('V')[0] }
      allow(pipe).to receive(:is_connected?) { pipe.peek_state == RubySMB::SMB2::Pipe::STATUS_CONNECTED }
      expect(pipe.is_connected?).to eq(true)
    end
  end

end