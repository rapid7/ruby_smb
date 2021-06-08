RSpec.describe RubySMB::Dcerpc::Winreg::RpcHkey do
  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::EnumValueRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :hkey }
  it { is_expected.to respond_to :dw_index }
  it { is_expected.to respond_to :lp_value_name }
  it { is_expected.to respond_to :pad }
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

  describe '#dw_index' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_index).to be_a BinData::Uint32le
    end
  end

  describe '#lp_value_name' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_value_name).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end
  end

  describe '#pad' do
    it 'is a string' do
      expect(packet.pad).to be_a BinData::String
    end

    it 'should keep #lp_type 4-byte aligned' do
      packet.lp_value_name = "test"
      expect(packet.lp_type.abs_offset % 4).to eq 0
    end
  end

  describe '#lp_type' do
    it 'is a Uint32Ptr structure' do
      expect(packet.lp_type).to be_a RubySMB::Dcerpc::Ndr::Uint32Ptr
    end
  end

  describe '#lp_data' do
    it 'is a ByteArrayPtr structure' do
      expect(packet.lp_data).to be_a RubySMB::Dcerpc::Ndr::ByteArrayPtr
    end
  end

  describe '#lpcb_data' do
    it 'is a Uint32Ptr structure' do
      expect(packet.lpcb_data).to be_a RubySMB::Dcerpc::Ndr::Uint32Ptr
    end
  end

  describe '#lpcb_len' do
    it 'is a Uint32Ptr structure' do
      expect(packet.lpcb_len).to be_a RubySMB::Dcerpc::Ndr::Uint32Ptr
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_ENUM_VALUE constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_ENUM_VALUE)
    end
  end

  describe '#pad_length' do
    it 'returns 0 when #lp_class is already 4-byte aligned' do
      packet.lp_value_name = 'align'
      expect(packet.pad_length).to eq 0
    end

    it 'returns 2 when #lp_class is only 2-byte aligned' do
      packet.lp_value_name = 'align' + 'A'
      expect(packet.pad_length).to eq 2
    end
  end
end
