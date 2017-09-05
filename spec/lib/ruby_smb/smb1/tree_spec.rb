require 'spec_helper'

RSpec.describe RubySMB::SMB1::Tree do
  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }

  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:tree_id) { 2049 }
  let(:path) { '\\192.168.1.1\example' }
  let(:response) {
    packet = RubySMB::SMB1::Packet::TreeConnectResponse.new
    packet.smb_header.tid = tree_id
    packet.parameter_block.access_rights.read("\xff\x01\x1f\x00")
    packet.data_block.service = 'A:'
    packet
  }
  subject(:tree) {
    described_class.new(client: client, share: path, response: response)
  }

  it { is_expected.to respond_to :client }
  it { is_expected.to respond_to :guest_permissions }
  it { is_expected.to respond_to :permissions }
  it { is_expected.to respond_to :share }
  it { is_expected.to respond_to :id }

  it 'inherits the client that spawned it' do
    expect(tree.client).to eq client
  end

  it 'inherits the permissions from the response packet' do
    expect(tree.permissions).to eq response.parameter_block.access_rights
  end

  it 'inherits the Tree id from the response packet' do
    expect(tree.id).to eq response.smb_header.tid
  end

  describe '#disconnect!' do
    let(:disco_req) { RubySMB::SMB1::Packet::TreeDisconnectRequest.new }
    let(:disco_resp) { RubySMB::SMB1::Packet::TreeDisconnectResponse.new }

    it 'sends a TreeDisconnectRequest with the Tree ID in the header' do
      allow(RubySMB::SMB1::Packet::TreeDisconnectRequest).to receive(:new).and_return(disco_req)
      modified_req = disco_req
      modified_req.smb_header.tid = tree.id
      expect(client).to receive(:send_recv).with(modified_req).and_return(disco_resp.to_binary_s)
      tree.disconnect!
    end

    it 'returns the NTStatus code from the response' do
      allow(client).to receive(:send_recv).and_return(disco_resp.to_binary_s)
      expect(tree.disconnect!).to eq disco_resp.status_code
    end
  end
end
