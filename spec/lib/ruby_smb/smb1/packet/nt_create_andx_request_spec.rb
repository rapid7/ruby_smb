RSpec.describe RubySMB::SMB1::Packet::NtCreateAndxRequest  do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NT_CREATE_ANDX' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_NT_CREATE_ANDX
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::ParameterBlock
    end

    it { is_expected.to respond_to :andx_block }
    it { is_expected.to respond_to :reserved }
    it { is_expected.to respond_to :name_length }
    it { is_expected.to respond_to :flags }
    it { is_expected.to respond_to :root_directory_fid }
    it { is_expected.to respond_to :desired_access }
    it { is_expected.to respond_to :allocation_size }
    it { is_expected.to respond_to :ext_file_attributes }
    it { is_expected.to respond_to :share_access }
    it { is_expected.to respond_to :create_disposition }
    it { is_expected.to respond_to :create_options }
    it { is_expected.to respond_to :impersonation_level }
    it { is_expected.to respond_to :security_flags }

    it 'has a AndXBlock' do
      expect(parameter_block.andx_block).to be_a RubySMB::SMB1::AndXBlock
    end

    it 'has a NtCreateAndxFlags bit-field' do
      expect(parameter_block.flags).to be_a RubySMB::SMB1::BitField::NtCreateAndxFlags
    end

    it 'has a SmbExtFileAttributes bit-field' do
      expect(parameter_block.ext_file_attributes).to be_a RubySMB::SMB1::BitField::SmbExtFileAttributes
    end

    it 'has a ShareAccess bit-field' do
      expect(parameter_block.share_access).to be_a RubySMB::SMB1::BitField::ShareAccess
    end

    it 'has a CreateOptions bit-field' do
      expect(parameter_block.create_options).to be_a RubySMB::SMB1::BitField::CreateOptions
    end

    it 'has a SecurityFlags bit-field' do
      expect(parameter_block.security_flags).to be_a RubySMB::SMB1::BitField::SecurityFlags
    end

    it 'has a #name_length field updated according to the #file_name length' do
      file_name = "test_name"
      packet.data_block.file_name = file_name
      expect(parameter_block.name_length).to eq(file_name.length)
    end

    describe '#desired_access' do
      it 'should be a DirectoryAccessMask when the file is a directory' do
        parameter_block.ext_file_attributes.directory = 1
        access_mask = parameter_block.desired_access.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::DirectoryAccessMask
      end

      it 'should be a FileAccessMask when the file is not a directory' do
        parameter_block.ext_file_attributes.directory = 0
        access_mask = parameter_block.desired_access.send(:current_choice)
        expect(access_mask.class).to eq RubySMB::SMB1::BitField::FileAccessMask
      end
    end

  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :file_name }

  end
end


