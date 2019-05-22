RSpec.describe RubySMB::Dcerpc::Winreg::RpcHkey do
  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::OpenKeyRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :hkey }
  it { is_expected.to respond_to :lp_sub_key }
  it { is_expected.to respond_to :pad }
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

  describe '#pad' do
    it 'is a string' do
      expect(packet.pad).to be_a BinData::String
    end

    it 'should keep #dw_options 4-byte aligned' do
      packet.lp_sub_key = "test"
      expect(packet.dw_options.abs_offset % 4).to eq 0
    end
  end

  describe '#dw_options' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_options).to be_a BinData::Uint32le
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

  describe '#pad_length' do
    it 'returns 0 when #dw_options is already 4-byte aligned' do
      packet.lp_sub_key = 'align'
      expect(packet.pad_length).to eq 0
    end

    it 'returns 2 when #dw_options is only 2-byte aligned' do
      packet.lp_sub_key = 'align' + 'A'
      expect(packet.pad_length).to eq 2
    end
  end
end

