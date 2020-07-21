RSpec.describe RubySMB::Dcerpc::Winreg::RpcHkey do
  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::QueryInfoKeyRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :hkey }
  it { is_expected.to respond_to :lp_class }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#hkey' do
    it 'is a RpcHkey structure' do
      expect(packet.hkey).to be_a RubySMB::Dcerpc::Winreg::RpcHkey
    end
  end

  describe '#lp_class' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_class).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_QUERY_INFO_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_QUERY_INFO_KEY)
    end
  end
end
