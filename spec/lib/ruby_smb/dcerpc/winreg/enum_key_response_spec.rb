RSpec.describe RubySMB::Dcerpc::Winreg::EnumKeyResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_name }
  it { is_expected.to respond_to :pad1 }
  it { is_expected.to respond_to :lp_class }
  it { is_expected.to respond_to :pad2 }
  it { is_expected.to respond_to :lpft_last_write_time }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
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

    it 'has the expected initial value' do
      expect(packet.lp_class).to eq({:buffer_length=>0, :maximum_length=>0, :buffer=>:null})
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
    it 'is a NdrFileTimePtr structure' do
      expect(packet.lpft_last_write_time).to be_a RubySMB::Dcerpc::Ndr::NdrFileTimePtr
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
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

