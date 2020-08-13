RSpec.describe RubySMB::Dcerpc::Winreg::RpcHkey do
  subject(:packet) { described_class.new }

  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::SaveKeyRequest do
  subject(:packet) { described_class.new }


  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it { is_expected.to respond_to :hkey }
  it { is_expected.to respond_to :lp_file }
  it { is_expected.to respond_to :pad }
  it { is_expected.to respond_to :lp_security_attributes }

  describe '#hkey' do
    it 'is a RpcHkey structure' do
      expect(packet.hkey).to be_a RubySMB::Dcerpc::Winreg::RpcHkey
    end
  end

  describe '#lp_file' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_file).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end
  end

  describe '#pad' do
    it 'is a string' do
      expect(packet.pad).to be_a BinData::String
    end

    it 'should keep #lp_security_attributes 4-byte aligned' do
      packet.lp_file = "test"
      expect(packet.lp_security_attributes.abs_offset % 4).to eq 0
    end
  end

  describe '#lp_security_attributes' do
    it 'is a PrpcSecurityAttributes structure' do
      expect(packet.lp_security_attributes).to be_a RubySMB::Dcerpc::PrpcSecurityAttributes
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_SAVE_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_SAVE_KEY)
    end
  end
end

