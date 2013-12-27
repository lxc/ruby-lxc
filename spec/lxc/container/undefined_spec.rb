require 'spec_helper'

describe LXC::Container do

  context 'container that is not defined' do

    let(:undefined_container) do
      LXC::Container.new('test_undefined')
    end

    it '#config_file_name' do
      config_path = File.join(LXC.default_config_path, 'test_undefined', 'config')
      expect(undefined_container.config_file_name).to eq(config_path)
    end

    it '#defined? should be false for undefined container' do
      expect(undefined_container.defined?).to be_false
    end

    it 'should not have an init pid' do
      expect(undefined_container.init_pid).to be_nil
    end

    it 'should not be in running state' do
      expect(undefined_container).to_not be_running
    end

    it 'should be in stopped state' do
      expect(undefined_container.state).to eq('STOPPED')
    end
  end
end
