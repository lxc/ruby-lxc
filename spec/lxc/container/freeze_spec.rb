require 'spec_helper'

describe LXC::Container do

  before(:all) do
    container.start
    container.wait('RUNNING',3)
  end

  after(:all) do
    container.shutdown
    container.wait('STOPPED',3)
  end

  context '#freeze' do

    before(:all) do
      container.freeze
      container.wait('FROZEN',3)
    end

    it 'should have init pid > 1' do
      expect(container.init_pid).to be > 1
    end

    it '#running? should be true' do
      expect(container).to be_running
    end

    it 'should be in frozen state' do
      expect(container.state).to eq('FROZEN')
    end
  end

  context '#unfreeze' do

    before(:all) do
      container.unfreeze
      container.wait('RUNNING', 3)
    end

    it 'should have init pid > 0' do
      expect(container.init_pid).to be > 1
    end

    it 'running? should return true' do
      expect(container).to be_running
    end

    it 'state should be running' do
      expect(container.state).to eq('RUNNING')
    end
  end
end
