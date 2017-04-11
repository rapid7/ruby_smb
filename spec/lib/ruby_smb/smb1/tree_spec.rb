require 'spec_helper'

RSpec.describe RubySMB::SMB1::Tree do
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(nil) }

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
    described_class.new(client:client, share:path, response:response )
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
end
