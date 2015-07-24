require 'ruby_smb/smb2'

RSpec.describe RubySMB::Smb2::Packet::WriteResponse do
  subject(:packet) do
    described_class.new(data)
  end

  context 'when parsing a packet' do
    let(:data) do
      [
        "fe534d4240000100000000000900010001000000000000000700000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "11000000740000000000000000000000"
      ].pack('H*')
    end

    it_behaves_like 'packet'
    it_behaves_like 'write_response_channel_info'

    specify do
      expect(packet.struct_size).to eq(17)
    end
    specify do
      expect(packet.reserved).to eq(0)
    end
    specify do
      expect(packet.byte_count).to eq(116)
    end
    specify do
      expect(packet.remaining).to eq(0)
    end

  end

  context 'when taking options' do

    subject(:packet) do
      described_class.new(
        struct_size: 17,
        byte_count: 116,
        remaining: 0,
        channel_info: '',
      )
    end

    it_behaves_like 'write_response_channel_info'

    specify do
      expect(packet.struct_size).to eq(17)
    end
    specify do
      expect(packet.reserved).to eq(0)
    end
    specify do
      expect(packet.byte_count).to eq(116)
    end
    specify do
      expect(packet.remaining).to eq(0)
    end
  end

  context 'when configured with a block' do

    subject(:packet) do
      described_class.new do |p|
        p.struct_size = 17
        p.byte_count = 116
        p.remaining = 0
        p.channel_info = ''
      end
    end

    it_behaves_like 'write_response_channel_info'

    specify do
      expect(packet.struct_size).to eq(17)
    end
    specify do
      expect(packet.reserved).to eq(0)
    end
    specify do
      expect(packet.byte_count).to eq(116)
    end
    specify do
      expect(packet.remaining).to eq(0)
    end
  end

end
