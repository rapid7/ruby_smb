RSpec.describe RubySMB::Dcerpc::Samr::PsamprServerName do
  subject(:packet) { described_class.new }

  it 'is a RubySMB::Field::Stringz16' do
    expect(packet).to be_a(RubySMB::Field::Stringz16)
  end
  it 'is a NdrPointer' do
    expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
    expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
  end
  it 'is four-bytes aligned' do
    expect(packet.eval_parameter(:byte_align)).to eq(4)
  end
  it 'has a referent which is two-bytes aligned' do
    expect(packet.eval_parameter(:referent_byte_align)).to eq(2)
  end
  it 'reads itself' do
    expect(packet.read(described_class.new('TestString!!').to_binary_s)).to eq('TestString!!'.encode('utf-16le'))
  end
end

RSpec.describe RubySMB::Dcerpc::Samr::SamrConnectRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :server_name }
  it { is_expected.to respond_to :desired_access }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#server_name' do
    it 'is a PsamprServerName structure' do
      expect(packet.server_name).to be_a RubySMB::Dcerpc::Samr::PsamprServerName
    end
  end
  describe '#desired_access' do
    it 'is a NdrUint32 structure' do
      expect(packet.desired_access).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_CONNECT constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_CONNECT)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(server_name: 'TestServer', desired_access: 555)
    expect(packet.read(new_class.to_binary_s)).to eq(
      {server_name: 'TestServer'.encode('utf-16le'), desired_access: 555}
    )
  end
end
