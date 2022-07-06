RSpec.describe RubySMB::Dcerpc::Dfsnm::NetrDfsRemoveStdRootResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#error_status' do
    it 'is a NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to NETR_DFS_REMOVE_STD_ROOT constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Dfsnm::NETR_DFS_REMOVE_STD_ROOT)
    end
  end
  it 'reads itself' do
    new_packet = described_class.new({
      error_status: 0
    })
    expected_output = {
      error_status: 0
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end


