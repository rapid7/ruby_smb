RSpec.describe RubySMB::Dcerpc::Winreg::RpcHkey do
  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::QueryValueRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :hkey }
  it { is_expected.to respond_to :lp_value_name }
  it { is_expected.to respond_to :lp_type }
  it { is_expected.to respond_to :lp_data }
  it { is_expected.to respond_to :lpcb_data }
  it { is_expected.to respond_to :lpcb_len }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#hkey' do
    it 'is a RpcHkey structure' do
      expect(packet.hkey).to be_a RubySMB::Dcerpc::Winreg::RpcHkey
    end
  end

  describe '#lp_value_name' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_value_name).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end
  end

  describe '#lp_type' do
    it 'is a Ndr::NdrUint32Ptr structure' do
      expect(packet.lp_type).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end

  describe '#lp_data' do
    it 'is a Ndr::NdrByteArrayPtr structure' do
      expect(packet.lp_data).to be_a RubySMB::Dcerpc::Ndr::NdrByteArrayPtr
    end
  end

  describe '#lpcb_data' do
    it 'is a Ndr::NdrUint32Ptr structure' do
      expect(packet.lpcb_data).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end

  describe '#lpcb_len' do
    it 'is a Ndr::NdrUint32Ptr structure' do
      expect(packet.lpcb_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_QUERY_VALUE constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_QUERY_VALUE)
    end
  end
end

