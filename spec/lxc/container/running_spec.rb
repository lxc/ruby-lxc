require 'spec_helper'
require 'timeout'
require 'tempfile'

describe LXC::Container do

  before(:all) do
    container.start
    container.wait('RUNNING', 3)
  end

  after(:all) do
    container.stop
    container.wait('STOPPED', 3)
  end

  context 'when container is running' do

    it 'should be have init pid greater that 0' do
      expect(container.init_pid).to be > 1
    end

    it '#running? should return true' do
      expect(container).to be_running
    end

    it 'its state should be "RUNNING"' do
      expect(container.state).to eq('RUNNING')
    end

    it 'should have loop back interfacce' do
      expect(container.interfaces).to include('lo')
    end

    it 'should have eth0 interfacce' do
      expect(container.interfaces).to include('eth0')
    end
  end

  context '#ip_addresses' do

    it 'should have a valid ip address' do
      Timeout::timeout(10) do
        while container.ip_addresses.empty?
          sleep 1
        end
      end
      expect(container.ip_addresses).to_not be_empty
      path = "/tmp/tc_lxc_running_ifconfig_eth0.#{Process.pid}"
      file = File.open(path, 'w+')
      begin
        nses = LXC::CLONE_NEWNET | LXC::CLONE_NEWUTS
        container.attach(wait: true, stdout:file, namespaces: nses) do
          LXC.run_command('ifconfig eth0')
        end
        file.rewind
        expect(file.readline).to match(/^eth0\s+Link\sencap:Ethernet\s+HWaddr\s/)
      ensure
        file.close
        File.unlink(path)
      end
    end
  end

  it 'should allow setting cgroup values' do
    max_mem = container.cgroup_item('memory.max_usage_in_bytes')
    cur_lim = container.cgroup_item('memory.limit_in_bytes')
    expect(container.set_cgroup_item('memory.limit_in_bytes', max_mem)).to_not be_nil
    expect(container.cgroup_item('memory.limit_in_bytes')).to_not eq(cur_lim)
  end

  context 'cloning a container' do

    it 'should allow cloning container' do
      if container.running?
        container.stop
        container.wait('STOPPED', 3)
      end
      expect(container.init_pid).to be_nil
      expect(container).to_not be_running
      expect(container.state).to eq('STOPPED')
      expect do
        begin
          clone = container.clone('test_clone')
          clone.start
          clone.stop
        ensure
          clone.destroy
        end
      end.to_not raise_error
    end
  end
end
