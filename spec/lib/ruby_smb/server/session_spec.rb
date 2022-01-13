RSpec.describe RubySMB::Server::Session do
  let(:user_id) { 'WORKGROUP\RubySMB' }
  subject(:session) { described_class.new(rand(0xffffffff), user_id: user_id) }

  it { is_expected.to respond_to :id }
  it { is_expected.to respond_to :key }
  it { is_expected.to respond_to :signing_required }
  it { is_expected.to respond_to :tree_connect_table }
  it { is_expected.to respond_to :creation_time }

  describe '#initialize' do
    it 'starts with no signing required' do
      expect(session.signing_required).to be_falsey
    end

    it 'starts with no tree connections' do
      expect(session.tree_connect_table).to be_empty
    end

    it 'starts in the in progress state' do
      expect(session.state).to be :in_progress
    end
  end

  describe '#is_anonymous' do
    it 'is false' do
      expect(session.is_anonymous).to be_falsey
    end

    context 'when the identity is set to anonymous' do
      let(:user_id) { RubySMB::Gss::Provider::IDENTITY_ANONYMOUS }

      it 'is true' do
        expect(session.is_anonymous).to be_truthy
      end
    end
  end
end
