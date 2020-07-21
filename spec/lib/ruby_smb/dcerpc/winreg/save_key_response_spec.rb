RSpec.describe RubySMB::Dcerpc::Winreg::SaveKeyResponse do
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
    it 'sets #opnum to REG_CREATE_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_CREATE_KEY)
    end
  end
end

