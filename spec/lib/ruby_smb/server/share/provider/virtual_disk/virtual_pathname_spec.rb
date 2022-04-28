RSpec.shared_context 'existing common' do
  describe '#atime' do
    it 'is a Time instance' do
      expect(virtual_pathname.atime).to be_a Time
    end
  end

  describe '#birthtime' do
    it 's a Time instance' do
      expect(virtual_pathname.birthtime).to be_a Time
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
    it 'is a Time instance' do
      expect(virtual_pathname.ctime).to be_a Time
    end
  end

  describe '#exist?' do
    it 'returns true' do
      expect(virtual_pathname.exist?).to be true
    end
  end

  describe '#grpowned?' do
    it 'returns true' do
      expect(virtual_pathname.grpowned?).to be true
    end
  end

  describe '#mtime' do
    it 'is a Time instance' do
      expect(virtual_pathname.mtime).to be_a Time
    end
  end

  describe '#owned?' do
    it 'returns true' do
      expect(virtual_pathname.owned?).to be true
    end
  end

  describe '#pipe?' do
    it 'returns false' do
      expect(virtual_pathname.pipe?).to be false
    end
  end

  describe '#readable?' do
    it 'returns true' do
      expect(virtual_pathname.readable?).to be true
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
    it 'returns 0' do
      expect(virtual_pathname.size).to be 0
    end
  end

  describe '#socket?' do
    it 'returns false' do
      expect(virtual_pathname.socket?).to be false
    end
  end

  describe '#stat' do
    it 'is a VirtualStat instance' do
      expect(virtual_pathname.stat).to be_a RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat
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
    it 'returns true' do
      expect(virtual_pathname.world_readable?).to be true
    end
  end

  describe '#world_writable?' do
    it 'returns false' do
      expect(virtual_pathname.world_writable?).to be false
    end
  end

  describe '#writable?' do
    it 'returns true' do
      expect(virtual_pathname.writable?).to be true
    end
  end
end

RSpec.describe RubySMB::Server::Share::Provider::VirtualDisk::VirtualPathname do
  let(:path) { 'path' }
  let(:leaf_path) { File.join(path, 'leaf') }
  subject(:virtual_pathname) { described_class.new({}, path) }

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

  describe '.basename' do
    # class methods return strings, instance methods return a new object
    it 'returns a String' do
      expect(described_class.basename('')).to be_a String
    end
  end

  describe '.cleanpath' do
    # class methods return strings, instance methods return a new object
    it 'returns a String' do
      expect(described_class.cleanpath('')).to be_a String
    end

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

  describe '.dirname' do
    # class methods return strings, instance methods return a new object
    it 'returns a String' do
      expect(described_class.dirname('')).to be_a String
    end
  end

  describe '.new' do
    it 'accepts a VirtualStat object' do
      stat = RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat.new
      expect(RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat).to_not receive(:new)
      inst = described_class.new({}, path, stat: stat)
      expect(inst.stat).to be stat
    end

    it 'accepts a VirtualStat Hash' do
      stat = { size: rand(0xFFFF) }
      expect(RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat).to receive(:new).and_call_original
      inst = described_class.new({}, path, stat: stat)
      expect(inst.stat).to_not be stat
      expect(inst.stat).to be_a RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat
      expect(inst.stat.size).to eq stat[:size]
    end
  end

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

  describe '#dirname' do
    it 'returns a new object' do
      expect(virtual_pathname.dirname).to be_a described_class
    end
  end

  describe '#extname' do
    it 'returns a String' do
      expect(virtual_pathname.extname).to be_a String
    end
  end

  describe '#join' do
    it 'returns a new object' do
      joined = virtual_pathname.join(leaf_path)
      expect(joined).to be_a described_class
      expect(joined).to_not eq virtual_pathname
    end
  end

  describe '#split' do
    it 'returns an array of two objects' do
      split = virtual_pathname.split
      expect(split.length).to be 2
      expect(split[0]).to be_a described_class
      expect(split[1]).to be_a described_class
    end
  end

  describe '#to_s' do
    it 'returns a string representation' do
      expect(virtual_pathname.to_s).to be_a String
    end
  end

  context 'when it is an absolute path' do
    subject(:virtual_pathname) { described_class.new({}, "#{File::SEPARATOR}testing") }

    describe '#absolute?' do
      it 'returns true' do
        expect(virtual_pathname.absolute?).to be true
      end
    end

    describe '#relative?' do
      it 'returns false' do
        expect(virtual_pathname.relative?).to be false
      end
    end
  end

  context 'when it is a relative path' do
    subject(:virtual_pathname) { described_class.new({}, ".#{File::SEPARATOR}testing") }

    describe '#absolute?' do
      it 'returns false' do
        expect(virtual_pathname.absolute?).to be false
      end
    end

    describe '#relative?' do
      it 'returns true' do
        expect(virtual_pathname.relative?).to be true
      end
    end
  end

  context 'when it is an existing directory' do
    let(:virtual_fs) { Hash.new }
    subject(:virtual_pathname) { described_class.new(virtual_fs, path, exist?: true, stat: { directory?: true }) }

    include_context 'existing common'

    context 'that is empty' do
      describe '#children' do
        it 'returns an empty array' do
          expect(virtual_pathname.children).to be_a Array
          expect(virtual_pathname.children).to be_empty
        end
      end

      describe '#entries' do
        it 'calls #children with_directories=false)' do
          expect(virtual_pathname).to receive(:children).with(false).and_call_original
          virtual_pathname.entries
        end

        it 'returns an empty array' do
          expect(virtual_pathname.entries).to be_a Array
          expect(virtual_pathname.entries).to be_empty
        end
      end
    end

    context 'that is populated' do
      before(:each) do
        virtual_fs[leaf_path] = described_class.new(virtual_fs, leaf_path)
      end

      describe '#children' do
        context 'when with_directories is true' do
          it 'returns an array of children' do
            expect(virtual_pathname.children(true)).to be_a Array
            expect(virtual_pathname.children(true)).to_not be_empty
            child = virtual_pathname.children(true).first
            expect(child).to be_a described_class
            expect(child.to_s).to eq leaf_path
          end
        end

        context 'when with_directories is false' do
          it 'returns an array of children' do
            expect(virtual_pathname.children(false)).to be_a Array
            expect(virtual_pathname.children(false)).to_not be_empty
            child = virtual_pathname.children(false).last
            expect(child).to be_a described_class
            expect(child.to_s).to eq File.basename(leaf_path)
          end
        end
      end

      describe '#entries' do
        it 'calls #children with_directories=false)' do
          expect(virtual_pathname).to receive(:children).with(false).and_call_original
          virtual_pathname.entries
        end

        it 'returns an array of children' do
          expect(virtual_pathname.entries).to be_a Array
          expect(virtual_pathname.entries).to_not be_empty
          child = virtual_pathname.entries.last
          expect(child).to be_a described_class
          expect(child.to_s).to eq File.basename(leaf_path)
        end
      end
    end

    describe '#executable?' do
      it 'returns true' do
        expect(virtual_pathname.executable?).to be true
      end
    end

    describe '#ftype' do
      it 'returns directory' do
        expect(virtual_pathname.ftype).to eq 'directory'
      end
    end

    describe '#zero?' do
      it 'returns false' do
        expect(virtual_pathname.zero?).to be false
      end
    end
  end

  context 'when it is an existing file' do
    subject(:virtual_pathname) { described_class.new({}, path, exist?: true, stat: { file?: true }) }

    include_context 'existing common'

    describe '#children' do
      it 'raises Errno::ENOTDIR' do
        expect { virtual_pathname.children }.to raise_error(Errno::ENOTDIR)
      end
    end

    describe '#entries' do
      it 'raises Errno::ENOTDIR' do
        expect { virtual_pathname.entries }.to raise_error(Errno::ENOTDIR)
      end
    end

    describe '#executable?' do
      it 'returns false' do
        expect(virtual_pathname.executable?).to be false
      end
    end

    describe '#ftype' do
      it 'returns file' do
        expect(virtual_pathname.ftype).to eq 'file'
      end
    end

    describe '#zero?' do
      it 'returns true' do
        expect(virtual_pathname.zero?).to be true
      end
    end
  end

  context 'when it does not exist' do
    # every attribute is tested to ensure they behave just like a Pathname object that doesn't exist
    subject(:virtual_pathname) { described_class.new({}, path, exist?: false) }

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

