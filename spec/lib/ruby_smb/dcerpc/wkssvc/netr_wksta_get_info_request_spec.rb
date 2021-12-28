RSpec.describe RubySMB::Dcerpc::Wkssvc::WkssvcIdentifyHandle do
  subject(:packet) { described_class.new }

  it 'is a Ndr::NdrWideStringPtr' do
    expect(packet).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringPtr)
  end
end

RSpec.describe RubySMB::Dcerpc::Wkssvc::NetrWkstaGetInfoRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :server_name }
  it { is_expected.to respond_to :level }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#server_name' do
    it 'is a WkssvcIdentifyHandle structure' do
      expect(packet.server_name).to be_a RubySMB::Dcerpc::Wkssvc::WkssvcIdentifyHandle
    end
  end
  describe '#level' do
    it 'is a NdrUint32 structure' do
      expect(packet.level).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to NETR_WKSTA_GET_INFO constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Wkssvc::NETR_WKSTA_GET_INFO)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(server_name: 'TestServer', level: 4)
    expect(packet.read(new_class.to_binary_s)).to eq(
      {server_name: 'TestServer'.encode('utf-16le'), level: 4}
    )
  end
end
