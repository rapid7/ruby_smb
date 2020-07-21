RSpec.describe RubySMB::Dcerpc::Winreg::PrpcHkey do
  subject(:packet) { described_class.new }

  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::CreateKeyResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :hkey }
  it { is_expected.to respond_to :lpdw_disposition }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#hkey' do
    it 'is a PrpcHkey structure' do
      expect(packet.hkey).to be_a RubySMB::Dcerpc::Winreg::PrpcHkey
    end
  end

  describe '#lpdw_disposition' do
    it 'is a NdrLpDword structure' do
      expect(packet.lpdw_disposition).to be_a RubySMB::Dcerpc::Ndr::NdrLpDword
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_CREATE_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_CREATE_KEY)
    end
  end
end

