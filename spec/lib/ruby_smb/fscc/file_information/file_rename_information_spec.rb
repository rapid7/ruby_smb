require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileRenameInformation do
  subject(:struct) { described_class.new }

  it { should respond_to :replace_if_exists }
  it { should respond_to :reserved_0 }
  it { should respond_to :reserved_1 }
  it { should respond_to :reserved_2 }
  it { should respond_to :root_firectory }
  it { should respond_to :file_name_length }
  it { should respond_to :file_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the length of the file_name field' do
    struct.file_name = 'Hello.txt'
    expect(struct.file_name_length).to eq struct.file_name.do_num_bytes
  end

  it 'encodes the file name in UTF-16LE' do
    name = 'Hello_world.txt'
    struct.file_name = name
    expect(struct.file_name.encode('utf-16le')).to eq name.encode('utf-16le')
  end

  describe 'reading in from a blob' do
    it 'uses the file_name_length to know when to stop reading' do
      name = 'Hello_world.txt'
      struct.file_name = name
      blob = struct.to_binary_s
      blob << 'AAAA'
      new_from_blob = described_class.read(blob)
      expect(new_from_blob.file_name.encode('utf-16le')).to eq name.encode('utf-16le')
    end
  end
end
