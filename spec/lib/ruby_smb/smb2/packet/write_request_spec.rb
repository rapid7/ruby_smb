require 'support/shared/examples/request'

RSpec.describe RubySMB::SMB2::Packet::WriteRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with packet bytes' do
    let(:data) do
      [
        "fe534d4240000100000000000900010000000000000000000700000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "31007000740000000000000000000000250000000000000001000000ffffffff" \
        "0000000000000000000000000000000005000b03100000007400000002000000" \
        "b810b810000000000200000000000100c84f324b7016d30112785a47bf6ee188" \
        "03000000045d888aeb1cc9119fe808002b1048600200000001000100c84f324b" \
        "7016d30112785a47bf6ee188030000002c1cb76c129840450300000000000000" \
        "01000000"
      ].pack('H*')
    end

    it_behaves_like "packet"
    it_behaves_like "request", RubySMB::SMB2::COMMANDS[:WRITE]

    specify 'struct_size' do
      expect(packet.struct_size).to eq(49)
    end

    specify 'data things' do
      expect(packet.data_offset).to eq(0x0070)
      expect(packet.data_length).to eq(116)
    end

    specify do
      expect(packet.file_offset).to eq(0)
    end

    specify do
      expect(packet.file_id).to eq(["250000000000000001000000ffffffff"].pack('H*'))
    end

    specify do
      expect(packet.channel).to eq(0)
    end

    specify do
      expect(packet.remaining_bytes).to eq(0)
    end

    specify do
      expect(packet.channel_info_offset).to eq(0)
    end

    specify do
      expect(packet.channel_info_length).to eq(0)
    end

    specify do
      expect(packet.flags).to eq(0)
    end

    specify do
      expect(packet.data).to eq([
        "05000b03100000007400000002000000b810b810000000000200000000000100" \
        "c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe80800" \
        "2b1048600200000001000100c84f324b7016d30112785a47bf6ee18803000000" \
        "2c1cb76c12984045030000000000000001000000"
      ].pack('H*'))
    end
  end

  describe '.new' do
    subject { described_class }

    specify do
      packet = described_class.new do |inst|
        inst.data = "asdf"
      end
      expect(packet.data_offset).to eq(0x70)
      expect(packet.data_length).to eq(4)
      expect(packet.data).to eq("asdf")
    end

    specify do
      packet = described_class.new do |inst|
        inst.data = ''
      end
      expect(packet.data_offset).to eq(0)
      expect(packet.data_length).to eq(0)
      expect(packet.data).to be_empty
    end

  end

end
