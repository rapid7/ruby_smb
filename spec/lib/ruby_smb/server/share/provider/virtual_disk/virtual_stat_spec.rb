RSpec.describe RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat do
  subject(:virtual_stat) { described_class.new }

  it { is_expected.to respond_to :atime }
  it { is_expected.to respond_to :blksize }
  it { is_expected.to respond_to :blockdev? }
  it { is_expected.to respond_to :blocks }
  it { is_expected.to respond_to :chardev? }
  it { is_expected.to respond_to :ctime }
  it { is_expected.to respond_to :dev }
  it { is_expected.to respond_to :directory? }
  it { is_expected.to respond_to :executable? }
  it { is_expected.to respond_to :file? }
  it { is_expected.to respond_to :ftype }
  it { is_expected.to respond_to :gid }
  it { is_expected.to respond_to :grpowned? }
  it { is_expected.to respond_to :ino }
  it { is_expected.to respond_to :mode }
  it { is_expected.to respond_to :mtime }
  it { is_expected.to respond_to :nlink }
  it { is_expected.to respond_to :owned? }
  it { is_expected.to respond_to :pipe? }
  it { is_expected.to respond_to :readable? }
  it { is_expected.to respond_to :setgid? }
  it { is_expected.to respond_to :setuid? }
  it { is_expected.to respond_to :size }
  it { is_expected.to respond_to :socket? }
  it { is_expected.to respond_to :sticky? }
  it { is_expected.to respond_to :symlink? }
  it { is_expected.to respond_to :uid }
  it { is_expected.to respond_to :world_readable? }
  it { is_expected.to respond_to :world_writable? }
  it { is_expected.to respond_to :writable? }
  it { is_expected.to respond_to :zero? }

  describe '#initialize' do
    it 'defaults to being a directory' do
      expect(virtual_stat.directory?).to be true
    end

    it 'throws an exception when it is both a file and a directory' do
      expect { described_class.new(directory?: true, file?: true) }.to raise_error(ArgumentError)
    end

    it 'throws an exception when it is neither a file or a directory' do
      expect { described_class.new(directory?: false, file?: false) }.to raise_error(ArgumentError)
    end

    it 'is a directory when it is a directory' do
      expect(described_class.new(directory?: true).directory?).to be true
    end

    it 'is a directory when not a file' do
      expect(described_class.new(file?: false).directory?).to be true
    end

    it 'is a file when it is a file' do
      expect(described_class.new(file?: true).file?).to be true
    end

    it 'is a file when not a directory' do
      expect(described_class.new(directory?: false).file?).to be true
    end
  end

  describe '#atime' do
    it 'is expected to default to now' do
      now = Time.now
      expect(Time).to receive(:now).and_return(now)
      expect(virtual_stat.atime).to eq now
    end
  end

  describe '#ctime' do
    it 'is expected to default to now' do
      now = Time.now
      expect(Time).to receive(:now).and_return(now)
      expect(virtual_stat.ctime).to eq now
    end
  end

  describe '#mtime' do
    it 'is expected to default to now' do
      now = Time.now
      expect(Time).to receive(:now).and_return(now)
      expect(virtual_stat.mtime).to eq now
    end
  end

  describe '#birthtime' do
    it 'is expected to default to now' do
      now = Time.now
      expect(Time).to receive(:now).and_return(now)
      expect(virtual_stat.birthtime).to eq now
    end
  end

  describe '#uid' do
    it 'is expected to default to the current process uid' do
      expect(virtual_stat.uid).to eq Process.uid
    end
  end

  describe '#gid' do
    it 'is expected to default to the current process gid' do
      expect(virtual_stat.gid).to eq Process.gid
    end
  end

  describe '#readable?' do
    it 'is expected to readable by default' do
      expect(virtual_stat.readable?).to be true
    end
  end

  describe '#writable?' do
    it 'is expected to writable by default' do
      expect(virtual_stat.writable?).to be true
    end
  end
end

