require 'spec_helper'
require 'smb2/client'
require 'support/mock_socket'

describe Smb2::Client do
  subject(:client) do
    described_class.new(dispatcher: dispatcher, username: username, password: password)
  end

  let(:username) { 'administrator' }
  let(:password) { 'P@ssword1' }

  let!(:dispatcher) do
    MockSocketDispatcher.new
  end

  context '#negotiate' do
    before do
      expect(dispatcher).to receive(:send_packet).with(kind_of Smb2::Packet)
      expect(dispatcher).to receive(:recv_packet).and_return(response.to_s)
    end

    let(:response) { Smb2::Packet::NegotiateResponse.new }

    specify do
      expect { client.negotiate }.not_to raise_error
      expect(client.sequence_number).to eq(0)
    end
    specify do
      expect { client.negotiate }.not_to raise_error
      expect(client.capabilities).to eq(response.capabilities)
    end
  end

end

