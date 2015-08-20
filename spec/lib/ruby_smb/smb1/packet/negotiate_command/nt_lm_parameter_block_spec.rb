require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::NegotiateCommand::NTLMParameterBlock do

  subject(:nt_lm_response_parameter_block) { described_class.new }

  it { is_expected.to respond_to :words_count }
  it { is_expected.to respond_to :dialect_index }
  it { is_expected.to respond_to :security_mode }
  it { is_expected.to respond_to :max_mpx_count }
  it { is_expected.to respond_to :max_number_vcs }
  it { is_expected.to respond_to :max_buffer_size }
  it { is_expected.to respond_to :max_raw_size }
  it { is_expected.to respond_to :session_key }
  it { is_expected.to respond_to :capabilities }
  it { is_expected.to respond_to :system_time }
  it { is_expected.to respond_to :server_time_zone }
  it { is_expected.to respond_to :challenge_length}

  describe 'words_count' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.words_count.num_bytes).to eq 1
    end
  end

  describe 'dialect_index' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.dialect_index.num_bytes).to eq 2
    end
  end

  describe 'security_mode' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.security_mode.num_bytes).to eq 1
    end
  end

  describe 'max_mpx_count' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.max_mpx_count.num_bytes).to eq 2
    end
  end

  describe 'max_number_vcs' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.max_number_vcs.num_bytes).to eq 2
    end
  end

  describe 'max_buffer_size' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.max_buffer_size.num_bytes).to eq 4
    end
  end

  describe 'max_raw_size' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.max_raw_size.num_bytes).to eq 4
    end
  end

  describe 'session_key' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.session_key.num_bytes).to eq 4
    end
  end

  describe 'capabilities' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.capabilities.num_bytes).to eq 4
    end
  end

  describe 'system_time' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.system_time.num_bytes).to eq 8
    end
  end

  describe 'server_time_zone' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.server_time_zone.num_bytes).to eq 2
    end
  end

  describe 'challenge_length' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(nt_lm_response_parameter_block.challenge_length.num_bytes).to eq 1
    end
  end

  describe '#nt_lm_negotiation?' do
    it "is true if word count is greater than 1" do
      expect(nt_lm_response_parameter_block.nt_lm_negotiation?).to be false
      nt_lm_response_parameter_block.words_count = 17
      expect(nt_lm_response_parameter_block.nt_lm_negotiation?).to be true
    end
  end
end