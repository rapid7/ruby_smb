require 'smb2'
require 'support/shared/examples/request'

RSpec.describe Smb2::Packet::CloseRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with packet bytes' do
    let(:data) do
      [
        "fe534d4240000100000000000600010000000000000000000a00000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "1800000000000000250000000000000001000000ffffffff"
      ].pack('H*')
    end

    it_behaves_like "request", Smb2::Commands::CLOSE

    specify do
      expect(packet.to_s).to eq(data)
    end

    specify 'struct_size' do
      expect(packet.struct_size).to eq(24)
    end

    specify 'file_id' do
      expect(packet.file_id).to eq(["250000000000000001000000ffffffff"].pack('H*'))
    end

    specify 'flags' do
      expect(packet.flags).to eq(0)
    end

  end

end
