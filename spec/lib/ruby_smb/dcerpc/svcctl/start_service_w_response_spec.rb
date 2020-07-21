RSpec.describe RubySMB::Dcerpc::Svcctl::StartServiceWResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to START_SERVICE_W constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::START_SERVICE_W)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      error_status: 3
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

