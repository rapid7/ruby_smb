RSpec.shared_examples 'packet' do
  context 'command' do
    specify do
      expect(Smb2::COMMANDS).to include(described_class::COMMAND)
      expect(subject.command).to eq(Smb2::COMMANDS[described_class::COMMAND])
    end
  end
end
