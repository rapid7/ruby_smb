RSpec.describe RubySMB::SMB2::BitField::HeaderFlags do
  subject(:flags) { described_class.new }

  it { is_expected.to respond_to :reserved1 }
  it { is_expected.to respond_to :replay_operation }
  it { is_expected.to respond_to :dfs_operation }
  it { is_expected.to respond_to :reserved2 }
  it { is_expected.to respond_to :reserved3 }
  it { is_expected.to respond_to :signed }
  it { is_expected.to respond_to :related_operations }
  it { is_expected.to respond_to :async_command }
  it { is_expected.to respond_to :reply }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@endian)).to eq :little
  end

  describe '#reserved1' do
    it 'should be a 2-bit field per the SMB spec' do
      expect(flags.reserved1).to be_a BinData::Bit2
    end
  end

  describe '#replay_operation' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.replay_operation).to be_a BinData::Bit1
    end

    context 'with only this field set' do
      it 'should equal 0x20000000' do
        flags.replay_operation = 1
        flag_value = flags.to_binary_s.unpack('N').first
        expect(flag_value).to eq 0x20000000
      end
    end
  end

  describe '#dfs_operation' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.dfs_operation).to be_a BinData::Bit1
    end

    context 'with only this field set' do
      it 'should equal 0x10000000' do
        flags.dfs_operation = 1
        flag_value = flags.to_binary_s.unpack('N').first
        expect(flag_value).to eq 0x10000000
      end
    end
  end

  describe '#reserved2' do
    it 'should be a 2-byte field per the SMB spec' do
      expect(flags.reserved2).to be_a BinData::Uint16le
    end
  end

  describe '#reserved3' do
    it 'should be a 4-bit field per the SMB spec' do
      expect(flags.reserved3).to be_a BinData::Bit4
    end
  end

  describe '#signed' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.signed).to be_a BinData::Bit1
    end

    context 'with only this field set' do
      it 'should equal 0x00000008' do
        flags.signed = 1
        flag_value = flags.to_binary_s.unpack('N').first
        expect(flag_value).to eq 0x00000008
      end
    end
  end

  describe '#related_operations' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.related_operations).to be_a BinData::Bit1
    end

    context 'with only this field set' do
      it 'should equal 0x00000004' do
        flags.related_operations = 1
        flag_value = flags.to_binary_s.unpack('N').first
        expect(flag_value).to eq 0x00000004
      end
    end
  end

  describe '#async_command' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.async_command).to be_a BinData::Bit1
    end
  end

  describe '#reply' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags.reply).to be_a BinData::Bit1
    end

    context 'with only this field set' do
      it 'should equal 0x00000001' do
        flags.reply = 1
        flag_value = flags.to_binary_s.unpack('N').first
        expect(flag_value).to eq 0x00000001
      end
    end
  end
end
