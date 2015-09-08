RSpec.describe RubySMB::SMB1::BitField::Capabilities do
  subject(:capabilities) { described_class.new }

  it { is_expected.to respond_to :level_2_oplocks }
  it { is_expected.to respond_to :nt_status }
  it { is_expected.to respond_to :rpc_remote_apis }
  it { is_expected.to respond_to :nt_smbs }
  it { is_expected.to respond_to :large_files }
  it { is_expected.to respond_to :unicode }
  it { is_expected.to respond_to :mpx_mode }
  it { is_expected.to respond_to :raw_mode }
  it { is_expected.to respond_to :large_writex }
  it { is_expected.to respond_to :large_readx }
  it { is_expected.to respond_to :info_level_passthru }
  it { is_expected.to respond_to :dfs }
  it { is_expected.to respond_to :reserved1 }
  it { is_expected.to respond_to :bulk_transfer }
  it { is_expected.to respond_to :nt_find }
  it { is_expected.to respond_to :lock_and_read }
  it { is_expected.to respond_to :unix }
  it { is_expected.to respond_to :reserved2 }
  it { is_expected.to respond_to :lwio }
  it { is_expected.to respond_to :extended_security }
  it { is_expected.to respond_to :reserved3 }
  it { is_expected.to respond_to :dynamic_reauth }
  it { is_expected.to respond_to :reserved4 }
  it { is_expected.to respond_to :compressed_data }
  it { is_expected.to respond_to :reserved5 }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@endian)).to eq :little
  end

  describe '#level_2_oplocks' do
    it 'is a 1-bit flag' do
      expect(capabilities.level_2_oplocks).to be_a BinData::Bit1
    end
  end

  describe '#nt_status' do
    it 'is a 1-bit flag' do
      expect(capabilities.nt_status).to be_a BinData::Bit1
    end
  end

  describe '#rpc_remote_apis' do
    it 'is a 1-bit flag' do
      expect(capabilities.rpc_remote_apis).to be_a BinData::Bit1
    end
  end

  describe '#nt_smbs' do
    it 'is a 1-bit flag' do
      expect(capabilities.nt_smbs).to be_a BinData::Bit1
    end
  end

  describe '#large_files' do
    it 'is a 1-bit flag' do
      expect(capabilities.large_files).to be_a BinData::Bit1
    end
  end

  describe '#unicode' do
    it 'is a 1-bit flag' do
      expect(capabilities.unicode).to be_a BinData::Bit1
    end
  end

  describe '#mpx_mode' do
    it 'is a 1-bit flag' do
      expect(capabilities.mpx_mode).to be_a BinData::Bit1
    end
  end

  describe '#raw_mode' do
    it 'is a 1-bit flag' do
      expect(capabilities.raw_mode).to be_a BinData::Bit1
    end
  end

  describe '#large_writex' do
    it 'is a 1-bit flag' do
      expect(capabilities.large_writex).to be_a BinData::Bit1
    end
  end

  describe '#large_readx' do
    it 'is a 1-bit flag' do
      expect(capabilities.large_readx).to be_a BinData::Bit1
    end
  end

  describe '#info_level_passthru' do
    it 'is a 1-bit flag' do
      expect(capabilities.info_level_passthru).to be_a BinData::Bit1
    end
  end

  describe '#dfs' do
    it 'is a 1-bit flag' do
      expect(capabilities.dfs).to be_a BinData::Bit1
    end
  end

  describe '#reserved1' do
    it 'is a 1-bit flag' do
      expect(capabilities.reserved1).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved1).to eq 0
    end
  end

  describe '#bulk_transfer' do
    it 'is a 1-bit flag' do
      expect(capabilities.bulk_transfer).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(capabilities.bulk_transfer).to eq 0
    end
  end

  describe '#nt_find' do
    it 'is a 1-bit flag' do
      expect(capabilities.nt_find).to be_a BinData::Bit1
    end
  end

  describe '#lock_and_read' do
    it 'is a 1-bit flag' do
      expect(capabilities.lock_and_read).to be_a BinData::Bit1
    end
  end

  describe '#unix' do
    it 'is a 1-bit flag' do
      expect(capabilities.unix).to be_a BinData::Bit1
    end
  end

  describe '#reserved2' do
    it 'is a 6-bit reserved space' do
      expect(capabilities.reserved2).to be_a BinData::Bit6
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved2).to eq 0
    end
  end

  describe '#lwio' do
    it 'is a 1-bit flag' do
      expect(capabilities.lwio).to be_a BinData::Bit1
    end
  end

  describe '#extended_security' do
    it 'is a 1-bit flag' do
      expect(capabilities.extended_security).to be_a BinData::Bit1
    end
  end

  describe '#reserved3' do
    it 'is a 1-bit flag' do
      expect(capabilities.reserved3).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved3).to eq 0
    end
  end

  describe '#dynamic_reauth' do
    it 'is a 1-bit flag' do
      expect(capabilities.dynamic_reauth).to be_a BinData::Bit1
    end
  end

  describe '#reserved4' do
    it 'is a 3-bit reserved space' do
      expect(capabilities.reserved4).to be_a BinData::Bit3
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved1).to eq 0
    end
  end

  describe '#compressed_data' do
    it 'is a 1-bit flag' do
      expect(capabilities.compressed_data).to be_a BinData::Bit1
    end
  end

  describe '#reserved5' do
    it 'is a 1-bit flag' do
      expect(capabilities.reserved5).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(capabilities.reserved5).to eq 0
    end
  end

end
