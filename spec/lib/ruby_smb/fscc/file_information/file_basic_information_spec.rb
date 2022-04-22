require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileBasicInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_BASIC_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :create_time }
  it { should respond_to :last_access }
  it { should respond_to :last_write }
  it { should respond_to :last_change }
  it { should respond_to :file_attributes }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the create time in a FileTime field' do
    expect(struct.create_time).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the last access time in a FileTime field' do
    expect(struct.last_access).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the last write time in a FileTime field' do
    expect(struct.last_write).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the last modified time in a FileTime field' do
    expect(struct.last_change).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the file attributes in a FileAttributes field' do
    expect(struct.file_attributes).to be_a RubySMB::Fscc::FileAttributes
  end

end
