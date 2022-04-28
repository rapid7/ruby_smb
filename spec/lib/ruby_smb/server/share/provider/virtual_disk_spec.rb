RSpec.describe RubySMB::Server::Share::Provider::VirtualDisk do
  let(:name) { 'vdisk' }
  subject(:virtual_disk) { described_class.new(name) }

  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :path }
  it { is_expected.to respond_to :type }
  context 'it provides the basic Hash methods' do
    it { is_expected.to respond_to :[] }
    it { is_expected.to respond_to :each }
    it { is_expected.to respond_to :each_key }
    it { is_expected.to respond_to :each_value }
    it { is_expected.to respond_to :keys }
    it { is_expected.to respond_to :length }
    it { is_expected.to respond_to :values }
  end

  describe '#add' do
    let(:path) { '/path' }

    it 'does not throw an exception if the stat object is not a file' do
      stat = RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat.new(file?: false)
      vp = RubySMB::Server::Share::Provider::VirtualDisk::VirtualPathname.new({}, path, stat: stat)
      expect { virtual_disk.add(vp) }.not_to raise_error
    end

    it 'throws an exception if the path is not absolute' do
      vp = RubySMB::Server::Share::Provider::VirtualDisk::VirtualPathname.new({}, path[1..])
      expect { virtual_disk.add(vp) }.to raise_error(ArgumentError)
    end

    it 'automatically creates parent directories' do
      expect(virtual_disk.length).to eq 1 # starts with just the root folder
      expect(RubySMB::Server::Share::Provider::VirtualDisk::VirtualPathname).to receive(:new).exactly(3).times.and_call_original
      virtual_disk.add(RubySMB::Server::Share::Provider::VirtualDisk::VirtualPathname.new({}, File.join(path, 'sub', 'dir')))
      expect(virtual_disk.length).to eq 4 # ends with the added item and 2 parent folders
    end
  end

  describe '#add_dynamic_file' do
    let(:path) { 'path' }
    let(:content) { 'Hello World!' }
    let(:block) { Proc.new { content } }

    before(:each) { allow(virtual_disk).to receive(:add) }

    it 'normalizes the path argument' do
      expect(RubySMB::Server::Share::Provider::VirtualDisk::VirtualDynamicFile).to receive(:new).with(virtual_disk, File::SEPARATOR + path, stat: nil, &block)
      virtual_disk.add_dynamic_file(path + '/dir/..', &block)
    end

    it 'initializes a new VirtualDynamicFile instance' do
      expect(RubySMB::Server::Share::Provider::VirtualDisk::VirtualDynamicFile).to receive(:new)
      virtual_disk.add_dynamic_file(path, &block)
    end

    it 'adds the mapped file' do
      expect(virtual_disk).to receive(:add)
      expect(virtual_disk.add_dynamic_file(path, &block))
    end

    it 'throws an exception if the stat object is not a file' do
      stat = RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat.new(file?: false)
      expect { virtual_disk.add_dynamic_file(path, stat: stat, &block) }. to raise_error(ArgumentError)
    end
  end

  describe '#add_mapped_file' do
    let(:path) { 'path' }
    let(:mapped_path) { 'mapped_path' }

    before(:each) { allow(virtual_disk).to receive(:add) }

    it 'normalizes the path argument' do
      expect(RubySMB::Server::Share::Provider::VirtualDisk::VirtualMappedFile).to receive(:new).with(virtual_disk, File::SEPARATOR + path, mapped_path)
      virtual_disk.add_mapped_file(path + '/dir/..', mapped_path)
    end

    it 'initializes a new VirtualMappedFile instance' do
      expect(RubySMB::Server::Share::Provider::VirtualDisk::VirtualMappedFile).to receive(:new)
      virtual_disk.add_mapped_file(path, mapped_path)
    end

    it 'adds the mapped file' do
      expect(virtual_disk).to receive(:add)
      expect(virtual_disk.add_mapped_file(path, mapped_path))
    end

    it 'throws an exception if the stat object is not a file' do
      stat = RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat.new(file?: false)
      expect { virtual_disk.add_mapped_file(path, mapped_path, stat: stat) }. to raise_error(ArgumentError)
    end
  end

  describe '#add_static_file' do
    let(:path) { 'path' }
    let(:content) { 'Hello World!' }

    before(:each) { allow(virtual_disk).to receive(:add) }

    it 'normalizes the path argument' do
      expect(RubySMB::Server::Share::Provider::VirtualDisk::VirtualStaticFile).to receive(:new).with(virtual_disk, File::SEPARATOR + path, content, stat: nil)
      virtual_disk.add_static_file(path + '/dir/..', content)
    end

    it 'initializes a new VirtualStaticFile instance' do
      expect(RubySMB::Server::Share::Provider::VirtualDisk::VirtualStaticFile).to receive(:new)
      virtual_disk.add_static_file(path, content)
    end

    it 'adds the mapped file' do
      expect(virtual_disk).to receive(:add)
      expect(virtual_disk.add_static_file(path, content))
    end

    it 'throws an exception if the stat object is not a file' do
      stat = RubySMB::Server::Share::Provider::VirtualDisk::VirtualStat.new(file?: false)
      expect { virtual_disk.add_static_file(path, content, stat: stat) }.to raise_error(ArgumentError)
    end
  end
end

