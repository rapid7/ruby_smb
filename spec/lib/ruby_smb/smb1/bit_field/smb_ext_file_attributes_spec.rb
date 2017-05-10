RSpec.describe RubySMB::SMB1::BitField::SmbExtFileAttributes do
  subject(:attrs) { described_class.new }

  it { is_expected.to respond_to :archive }
  it { is_expected.to respond_to :directory }
  it { is_expected.to respond_to :normal }
  it { is_expected.to respond_to :system }
  it { is_expected.to respond_to :hidden }
  it { is_expected.to respond_to :read_only }
  it { is_expected.to respond_to :compressed }
  it { is_expected.to respond_to :temporary }
  it { is_expected.to respond_to :write_through }
  it { is_expected.to respond_to :no_buffering }
  it { is_expected.to respond_to :random_access }
  it { is_expected.to respond_to :sequential_scan }
  it { is_expected.to respond_to :delete_on_close }
  it { is_expected.to respond_to :backup_semantics }
  it { is_expected.to respond_to :posix_semantics }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'read_only' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.read_only).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :read_only, 'V', 0x00000001
  end

  describe 'hidden' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.hidden).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :hidden, 'V', 0x00000002
  end

  describe 'system' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.system).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :system, 'V', 0x00000004
  end

  describe 'directory' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.directory).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :directory, 'V', 0x00000010
  end

  describe 'archive' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.archive).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :archive, 'V', 0x00000020
  end

  describe 'normal' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.normal).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :normal, 'V', 0x00000080
  end

  describe 'temporary' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.temporary).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :temporary, 'V', 0x00000100
  end

  describe 'compressed' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.compressed).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :compressed, 'V', 0x00000800
  end

  describe 'posix_semantics' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.posix_semantics).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :posix_semantics, 'V', 0x01000000
  end

  describe 'backup_semantics' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.backup_semantics).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :backup_semantics, 'V', 0x02000000
  end

  describe 'delete_on_close' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.delete_on_close).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :delete_on_close, 'V', 0x04000000
  end

  describe 'sequential_scan' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.sequential_scan).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :sequential_scan, 'V', 0x08000000
  end

  describe 'random_access' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.random_access).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :random_access, 'V', 0x10000000
  end

  describe 'no_buffering' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.no_buffering).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :no_buffering, 'V', 0x20000000
  end

  describe 'write_through' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(attrs.write_through).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :write_through, 'V', 0x80000000
  end

end
