RSpec.describe RubySMB::SMB2::Packet::CloseResponse do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with packet bytes' do
    let(:data) do
      [
        "fe534d4240000100000000000600010001000000000000001d00000000000000" \
        "fffe000001000000290000000004000000000000000000000000000000000000" \
        "3c00000000000000000000000000000000000000000000000000000000000000" \
        "00000000000000000000000000000000000000000000000000000000"
      ].pack('H*')
    end

    it_behaves_like "packet"

    specify 'struct_size' do
      expect(packet.struct_size).to eq(60)
    end

    specify 'flags' do
      expect(packet.flags).to eq(0)
    end

    specify 'last_access_time' do
      expect(packet.last_access_time).to eq(0)
    end

    specify 'last_write_time' do
      expect(packet.last_write_time).to eq(0)
    end

    specify 'last_change_time' do
      expect(packet.last_change_time).to eq(0)
    end

    specify 'allocation_size' do
      expect(packet.allocation_size).to eq(0)
    end

    specify 'end_of_file' do
      expect(packet.end_of_file).to eq(0)
    end

    specify 'file_attributes' do
      expect(packet.file_attributes).to eq(0)
    end

  end

end