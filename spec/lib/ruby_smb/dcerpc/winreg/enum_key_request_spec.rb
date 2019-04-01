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
  it { is_expected.to respond_to :pad1 }
  it { is_expected.to respond_to :lp_class }
  it { is_expected.to respond_to :pad2 }
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
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_index).to be_a BinData::Uint32le
    end
  end

  describe '#lp_name' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_name).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end
  end

  describe '#pad1' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #lp_class 4-byte aligned' do
      packet.lp_name = "test"
      expect(packet.lp_class.abs_offset % 4).to eq 0
    end
  end

  describe '#lp_class' do
    it 'is a PrrpUnicodeString structure' do
      expect(packet.lp_class).to be_a RubySMB::Dcerpc::PrrpUnicodeString
    end

    it 'has a initial value of 0' do
      expect(packet.lp_class).to eq(0)
    end
  end

  describe '#pad2' do
    it 'is a string' do
      expect(packet.pad2).to be_a BinData::String
    end

    it 'should keep #lpft_last_write_time 4-byte aligned' do
      packet.lp_class = "test"
      expect(packet.lpft_last_write_time.abs_offset % 4).to eq 0
    end
  end

  describe '#lpft_last_write_time' do
    it 'is a NdrLpFileTime structure' do
      expect(packet.lpft_last_write_time).to be_a RubySMB::Dcerpc::Ndr::NdrLpFileTime
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_ENUM_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_ENUM_KEY)
    end
  end

  describe '#pad_length1' do
    it 'returns 0 when #lp_class is already 4-byte aligned' do
      packet.lp_name = 'align'
      expect(packet.pad_length1).to eq 0
    end

    it 'returns 2 when #lp_class is only 2-byte aligned' do
      packet.lp_name = 'align' + 'A'
      expect(packet.pad_length1).to eq 2
    end
  end

  describe '#pad_length2' do
    it 'returns 0 when #lpft_last_write_time is already 4-byte aligned' do
      packet.lp_class = 'align'
      expect(packet.pad_length2).to eq 0
    end

    it 'returns 2 when #lpft_last_write_time is only 2-byte aligned' do
      packet.lp_class = 'align' + 'A'
      expect(packet.pad_length2).to eq 2
    end
  end
end
