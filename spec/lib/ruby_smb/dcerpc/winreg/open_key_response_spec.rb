RSpec.describe RubySMB::Dcerpc::Winreg::PrpcHkey do
  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::OpenKeyResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :phk_result }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#phk_result' do
    it 'is a PrpcHkey structure' do
      expect(packet.phk_result).to be_a RubySMB::Dcerpc::Winreg::PrpcHkey
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_OPEN_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_OPEN_KEY)
    end
  end
end
