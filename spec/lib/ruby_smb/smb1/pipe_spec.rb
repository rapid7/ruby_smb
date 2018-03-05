RSpec.describe RubySMB::SMB1::Pipe do

  let(:peek_nmpipe_response) {
    packet = RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse.new
    packet.data_block.trans_parameters.read("\x10\x20\x00\x00\x03\x00")
    packet
  }

  describe RubySMB::SMB1::Pipe do
    it { expect(described_class).to be < RubySMB::SMB1::File }
  end

  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(double('socket')) }
  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:connect_response) {
    packet = RubySMB::SMB1::Packet::TreeConnectResponse.new
    packet.smb_header.tid = 2051
    packet.parameter_block.guest_access_rights.read("\xff\x01\x1f\x00")
    packet.parameter_block.access_rights.read("\xff\x01\x1f\x01")
    packet
  }
  let(:tree) { RubySMB::SMB1::Tree.new(client: client, share: '\\1.2.3.4\IPC$', response: connect_response) }
  let(:nt_create_andx_response) {
    response = RubySMB::SMB1::Packet::NtCreateAndxResponse.new
    response.parameter_block.ext_file_attributes = { normal: 1 }
    response.parameter_block.fid = 0x4000
    response.parameter_block.last_access_time = DateTime.parse("2017-09-20T1:1:1")
    response.parameter_block.last_change_time = DateTime.parse("2017-09-22T2:2:2")
    response.parameter_block.last_write_time  = DateTime.parse("2017-09-25T3:3:3")
    response.parameter_block.end_of_file = 53
    response.parameter_block.allocation_size = 4096
    response
  }
  let(:filename) { 'msf-pipe' }

  subject(:pipe) {
    described_class.new(tree: tree, response: nt_create_andx_response, name: filename)
  }

  describe '#peek_available' do
    it 'reads the correct number of bytes available' do
      allow(pipe).to receive(:peek) { peek_nmpipe_response }
      allow(pipe).to receive(:peek_available) { pipe.peek.data_block.trans_parameters.read_data_available }
      expect(pipe.peek_available).to eq(0x2010)
    end
  end

  describe '#peek_state' do
    it 'reads the correct state of the pipe' do
      allow(pipe).to receive(:peek) { peek_nmpipe_response }
      allow(pipe).to receive(:peek_state) { pipe.peek.data_block.trans_parameters.pipe_state }
      expect(pipe.peek_state).to eq(RubySMB::SMB1::Pipe::STATUS_OK)
    end
  end

  describe '#is_connected?' do
    it 'identifies that the pipe is connected from the status' do
      allow(pipe).to receive(:peek) { peek_nmpipe_response }
      allow(pipe).to receive(:peek_state) { pipe.peek.data_block.trans_parameters.pipe_state }
      allow(pipe).to receive(:is_connected?) { pipe.peek_state == RubySMB::SMB1::Pipe::STATUS_OK }
      expect(pipe.is_connected?).to eq(true)
    end
  end

end