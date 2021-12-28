RSpec.describe RubySMB::Dcerpc::Winreg::RpcHkey do
  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::OpenKeyRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :hkey }
  it { is_expected.to respond_to :lp_sub_key }
  it { is_expected.to respond_to :dw_options }
  it { is_expected.to respond_to :sam_desired }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#hkey' do
    it 'is a RpcHkey structure' do
      expect(packet.hkey).to be_a RubySMB::Dcerpc::Winreg::RpcHkey
    end
  end

  describe '#lp_sub_key' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_sub_key).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end
  end

  describe '#dw_options' do
    it 'is a NdrUint32' do
      expect(packet.dw_options).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#sam_desired' do
    it 'is a Regsam structure' do
      expect(packet.sam_desired).to be_a RubySMB::Dcerpc::Winreg::Regsam
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_OPEN_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_OPEN_KEY)
    end
  end
end

