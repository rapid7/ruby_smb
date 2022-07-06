RSpec.describe RubySMB::Dcerpc::Dfsnm::NetrDfsAddStdRootRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :server_name }
  it { is_expected.to respond_to :root_share }
  it { is_expected.to respond_to :comment }
  it { is_expected.to respond_to :api_flags }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#server_name' do
    it 'is a NdrConfVarWideStringz structure' do
      expect(packet.server_name).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end
  describe '#root_share' do
    it 'is a NdrConfVarWideStringz structure' do
      expect(packet.root_share).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end
  describe '#comment' do
    it 'is a NdrConfVarWideStringz structure' do
      expect(packet.comment).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end
  describe '#api_flags' do
    it 'is a NdrUint32 structure' do
      expect(packet.api_flags).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to NETR_DFS_ADD_STD_ROOT constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Dfsnm::NETR_DFS_ADD_STD_ROOT)
    end
  end
  it 'reads itself' do
    new_packet = described_class.new({
      server_name: 'serverName',
      root_share: 'rootShare',
      comment: 'comment'
    })
    expected_output = {
      server_name: 'serverName'.encode('utf-16le'),
      root_share: 'rootShare'.encode('utf-16le'),
      comment: 'comment'.encode('utf-16le'),
      api_flags: 0
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end


