require 'spec_helper'

RSpec.describe RubySMB::Dispatcher::Base do

  subject(:dispatcher) { described_class.new }

  describe '#nbss' do
    it 'returns the size of the packet to the packet in 4 bytes' do
      packet = RubySMB::SMB1::Packet::NegotiateRequest.new
      packet_size = packet.do_num_bytes
      expect( dispatcher.nbss(packet) ).to eq "\x00\x00\x00\x23"
    end
  end

  it 'raises NotImplementedError on #send_packet' do
    expect{ dispatcher.send_packet("foo") }.to raise_error(NotImplementedError)
  end

  it 'raises NotImplementedError on #recv_packet' do
    expect{ dispatcher.recv_packet }.to raise_error(NotImplementedError)
  end
end