require 'spec_helper'

RSpec.describe RubySMB::Dcerpc::Bind do

  describe '#initialize' do

    let(:bind){described_class.new(endpoint: RubySMB::Dcerpc::Srvsvc)}
    let(:abstract_syntax){bind.p_context_elem.p_cont_elem[0].abstract_syntax}

    it 'should set the abstract syntax to SrvsvcSyntax' do
      expect(abstract_syntax).to eq RubySMB::Dcerpc::SrvsvcSyntax.new
    end
  end
end
