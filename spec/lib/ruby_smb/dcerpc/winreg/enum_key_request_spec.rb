RSpec.describe RubySMB::Dcerpc::Winreg::RpcHkey do
  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::EnumKeyRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :hkey }
  it { is_expected.to respond_to :dw_index }
  it { is_expected.to respond_to :lp_name }
  it { is_expected.to respond_to :lp_class }
  it { is_expected.to respond_to :lpft_last_write_time }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#hkey' do
    it 'is a RpcHkey structure' do
      expect(packet.hkey).to be_a RubySMB::Dcerpc::Winreg::RpcHkey
    end
  end

  describe '#dw_index' do
    it 'is a NdrUint32' do
      expect(packet.dw_index).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lp_name' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_name).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end
  end

  describe '#lp_class' do
    it 'is a PrrpUnicodeString structure' do
      expect(packet.lp_class).to be_a RubySMB::Dcerpc::PrrpUnicodeString
    end
  end

  describe '#lpft_last_write_time' do
    it 'is a NdrFileTimePtr structure' do
      expect(packet.lpft_last_write_time).to be_a RubySMB::Dcerpc::Ndr::NdrFileTimePtr
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_ENUM_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_ENUM_KEY)
    end
  end
end
