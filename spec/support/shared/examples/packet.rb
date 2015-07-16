RSpec.shared_examples 'packet' do

  context 'command' do

    specify do
      expect(Smb2::COMMANDS).to include(subject.class::COMMAND)
      expect(subject.command).to eq(Smb2::COMMANDS[subject.class::COMMAND])
    end

    it { is_expected.to respond_to(:magic) }
    it { is_expected.to respond_to(:header_len) }
    it { is_expected.to respond_to(:credit_charge) }

    # Skip nt_status because it only makes sense for responses

    it { is_expected.to respond_to(:command) }
    it { is_expected.to respond_to(:credits_requested) }
    it { is_expected.to respond_to(:header_flags) }
    it { is_expected.to respond_to(:chain_offset) }
    it { is_expected.to respond_to(:command_seq) }
    it { is_expected.to respond_to(:process_id) }
    it { is_expected.to respond_to(:tree_id) }
    it { is_expected.to respond_to(:session_id) }
    it { is_expected.to respond_to(:signature) }

  end

end
