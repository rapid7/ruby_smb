RSpec.describe RubySMB::Dcerpc::Winreg::EnumValueResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_value_name }
  it { is_expected.to respond_to :pad }
  it { is_expected.to respond_to :lp_type }
  it { is_expected.to respond_to :lp_data }
  it { is_expected.to respond_to :lpcb_data }
  it { is_expected.to respond_to :lpcb_len }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
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
    it 'is a NdrLpDword structure' do
      expect(packet.lp_type).to be_a RubySMB::Dcerpc::Ndr::NdrLpDword
    end
  end

  describe '#lp_data' do
    it 'is a NdrLpByte structure' do
      expect(packet.lp_data).to be_a RubySMB::Dcerpc::Ndr::NdrLpByte
    end
  end

  describe '#lpcb_data' do
    it 'is a NdrLpDword structure' do
      expect(packet.lpcb_data).to be_a RubySMB::Dcerpc::Ndr::NdrLpDword
    end
  end

  describe '#lpcb_len' do
    it 'is a NdrLpDword structure' do
      expect(packet.lpcb_len).to be_a RubySMB::Dcerpc::Ndr::NdrLpDword
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
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

