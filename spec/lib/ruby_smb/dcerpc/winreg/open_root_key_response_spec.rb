RSpec.describe RubySMB::Dcerpc::Winreg::PrpcHkey do
  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::OpenRootKeyResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :ph_key}
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#ph_key' do
    it 'is a PrpcHkey structure' do
      expect(packet.ph_key).to be_a RubySMB::Dcerpc::Winreg::PrpcHkey
    end
  end

  describe '#error_status' do
    it 'is a NdrUint32' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    context 'when an #opnum parameter is provided' do
      it 'sets #opnum to the parameter\'s value' do
        packet = described_class.new(opnum: RubySMB::Dcerpc::Winreg::OPEN_HKLM)
        expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::OPEN_HKLM)
      end
    end
  end
end
