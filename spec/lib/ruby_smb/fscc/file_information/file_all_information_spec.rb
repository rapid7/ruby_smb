require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileAllInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_ALL_INFORMATION
  end

  subject(:struct) { described_class.new }

 it { should respond_to :basic_information }
 it { should respond_to :standard_information }
 it { should respond_to :internal_information }
 it { should respond_to :ea_information }
 it { should respond_to :access_information }
 it { should respond_to :position_information }
 it { should respond_to :mode_information }
 it { should respond_to :alignment_information }
 it { should respond_to :name_information }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the basic information in a FileBasicInformation field' do
    expect(struct.basic_information).to be_a RubySMB::Fscc::FileInformation::FileBasicInformation
  end

  it 'tracks the standard information in a FileStandardInformation field' do
    expect(struct.standard_information).to be_a RubySMB::Fscc::FileInformation::FileStandardInformation
  end

  it 'tracks the internal information in a FileInternalInformation field' do
    expect(struct.internal_information).to be_a RubySMB::Fscc::FileInformation::FileInternalInformation
  end

  it 'tracks the ea information in a FileEaInformation field' do
    expect(struct.ea_information).to be_a RubySMB::Fscc::FileInformation::FileEaInformation
  end

  it 'tracks the access information in a FileAccessInformation field' do
    expect(struct.access_information).to be_a RubySMB::Fscc::FileInformation::FileAccessInformation
  end

  it 'tracks the position information in a FilePositionInformation field' do
    expect(struct.position_information).to be_a RubySMB::Fscc::FileInformation::FilePositionInformation
  end

  it 'tracks the mode information in a FileModeInformation field' do
    expect(struct.mode_information).to be_a RubySMB::Fscc::FileInformation::FileModeInformation
  end

  it 'tracks the alignment information in a FileAlignmentInformation field' do
    expect(struct.alignment_information).to be_a RubySMB::Fscc::FileInformation::FileAlignmentInformation
  end

  it 'tracks the name information in a FileNameInformation field' do
    expect(struct.name_information).to be_a RubySMB::Fscc::FileInformation::FileNameInformation
  end
end

