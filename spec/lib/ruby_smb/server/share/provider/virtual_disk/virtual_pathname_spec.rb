RSpec.describe RubySMB::Server::Share::Provider::VirtualDisk::VirtualPathname do
  subject(:virtual_pathname) { described_class.new({}, 'testing') }

  it { is_expected.to respond_to :atime }
  it { is_expected.to respond_to :birthtime }
  it { is_expected.to respond_to :blockdev? }
  it { is_expected.to respond_to :chardev? }
  it { is_expected.to respond_to :ctime }
  it { is_expected.to respond_to :directory? }
  it { is_expected.to respond_to :executable? }
  it { is_expected.to respond_to :file? }
  it { is_expected.to respond_to :ftype }
  it { is_expected.to respond_to :grpowned? }
  it { is_expected.to respond_to :mtime }
  it { is_expected.to respond_to :owned? }
  it { is_expected.to respond_to :pipe? }
  it { is_expected.to respond_to :readable? }
  it { is_expected.to respond_to :setgid? }
  it { is_expected.to respond_to :setuid? }
  it { is_expected.to respond_to :size }
  it { is_expected.to respond_to :socket? }
  it { is_expected.to respond_to :sticky? }
  it { is_expected.to respond_to :symlink? }
  it { is_expected.to respond_to :world_readable? }
  it { is_expected.to respond_to :world_writable? }
  it { is_expected.to respond_to :writable? }
  it { is_expected.to respond_to :zero? }

  describe '#initialize' do
    it 'defaults to existing' do
      expect(virtual_pathname.exist?).to be true
    end

    it 'defaults to being a directory' do
      expect(virtual_pathname.directory?).to be true
    end

    it 'defaults to having a stat object' do
      expect(virtual_pathname.stat).to be_truthy
    end
  end

  describe '#cleanpath' do
    it 'normalizes relative paths' do
      expect(described_class.cleanpath('')).to eq '.'
      expect(described_class.cleanpath('.')).to eq '.'
      expect(described_class.cleanpath('./')).to eq '.'
      expect(described_class.cleanpath('./.')).to eq '.'
    end

    it 'normalizes absolute paths' do
      expect(described_class.cleanpath('/')).to eq '/'
      expect(described_class.cleanpath('/.')).to eq '/'
      expect(described_class.cleanpath('/..')).to eq '/'
      expect(described_class.cleanpath('/test/..')).to eq '/'
      expect(described_class.cleanpath('/test/../')).to eq '/'
    end
  end

  context 'when it does not exist' do
    # every attribute is tested to ensure they behave just like a Pathname object that doesn't exist
    subject(:virtual_pathname) { described_class.new({}, 'testing', exist?: false) }

    describe '#atime' do
      it 'raises Errno::ENOENT' do
        expect { virtual_pathname.atime }.to raise_error(Errno::ENOENT)
      end
    end

    describe '#birthtime' do
      it 'raises Errno::ENOENT' do
        expect { virtual_pathname.birthtime }.to raise_error(Errno::ENOENT)
      end
    end

    describe '#blockdev?' do
      it 'returns false' do
        expect(virtual_pathname.blockdev?).to be false
      end
    end

    describe '#chardev?' do
      it 'returns false' do
        expect(virtual_pathname.chardev?).to be false
      end
    end

    describe '#ctime' do
      it 'raises Errno::ENOENT' do
        expect { virtual_pathname.ctime }.to raise_error(Errno::ENOENT)
      end
    end

    describe '#directory?' do
      it 'returns false' do
        expect(virtual_pathname.directory?).to be false
      end
    end

    describe '#executable?' do
      it 'returns false' do
        expect(virtual_pathname.executable?).to be false
      end
    end

    describe '#exist?' do
      it 'returns false' do
        expect(virtual_pathname.exist?).to be false
      end
    end

    describe '#file?' do
      it 'returns false' do
        expect(virtual_pathname.file?).to be false
      end
    end

    describe '#ftype' do
      it 'raises Errno::ENOENT' do
        expect { virtual_pathname.ftype }.to raise_error(Errno::ENOENT)
      end
    end

    describe '#grpowned?' do
      it 'returns false' do
        expect(virtual_pathname.grpowned?).to be false
      end
    end

    describe '#mtime' do
      it 'raises Errno::ENOENT' do
        expect { virtual_pathname.mtime }.to raise_error(Errno::ENOENT)
      end
    end

    describe '#owned?' do
      it 'returns false' do
        expect(virtual_pathname.owned?).to be false
      end
    end

    describe '#pipe?' do
      it 'returns false' do
        expect(virtual_pathname.pipe?).to be false
      end
    end

    describe '#readable?' do
      it 'returns false' do
        expect(virtual_pathname.readable?).to be false
      end
    end

    describe '#setgid?' do
      it 'returns false' do
        expect(virtual_pathname.setgid?).to be false
      end
    end

    describe '#setuid?' do
      it 'returns false' do
        expect(virtual_pathname.setuid?).to be false
      end
    end

    describe '#size' do
      it 'raises Errno::ENOENT' do
        expect { virtual_pathname.size }.to raise_error(Errno::ENOENT)
      end
    end

    describe '#socket?' do
      it 'returns false' do
        expect(virtual_pathname.socket?).to be false
      end
    end

    describe '#stat' do
      it 'raises Errno::ENOENT' do
        expect { virtual_pathname.stat }.to raise_error(Errno::ENOENT)
      end
    end

    describe '#sticky?' do
      it 'returns false' do
        expect(virtual_pathname.sticky?).to be false
      end
    end

    describe '#symlink?' do
      it 'returns false' do
        expect(virtual_pathname.symlink?).to be false
      end
    end

    describe '#world_readable?' do
      it 'returns nil' do
        expect(virtual_pathname.world_readable?).to be_nil
      end
    end

    describe '#world_writable?' do
      it 'returns nil' do
        expect(virtual_pathname.world_writable?).to be_nil
      end
    end

    describe '#writable?' do
      it 'returns false' do
        expect(virtual_pathname.writable?).to be false
      end
    end

    describe '#zero?' do
      it 'returns false' do
        expect(virtual_pathname.zero?).to be false
      end
    end
  end
end

