$:.unshift File.expand_path(File.join(File.dirname(__FILE__), 'lib'))

require 'test/unit'
require 'tempfile'
require 'lxc'

class TestLXCRunning < Test::Unit::TestCase
  def setup
    if Process::Sys::geteuid != 0
      raise 'This test must be ran as root'
    end
    @name = 'test'
    @container = LXC::Container.new(@name)
    @container.create('ubuntu') unless @container.defined?
    @container.start
  end

  def teardown
    @container.shutdown(3) rescue nil
    if @container.running?
      @container.stop
      @container.wait(:stopped, 3)
    end
  end

  def test_container_running
    @container.wait(:running, 3)
    assert(@container.init_pid > 1)
    assert(@container.running?)
    assert_equal(:running, @container.state)
  end

  def test_container_config_item
    key = 'lxc.network.0.type'
    assert_equal('veth', @container.running_config_item(key))
  end

  def test_container_interfaces
    assert_equal(['eth0', 'lo'], @container.interfaces.sort)
  end

  def test_container_ip_addresses
    ips = nil
    10.times do
      ips = @container.ip_addresses
      break unless ips.empty?
      sleep 1
    end
    assert(ips.length > 0)
    path = "/tmp/tc_lxc_running_ifconfig_eth0.#{Process.pid}"
    file = File.open(path, 'w+')
    begin
      opts = {
        :wait       => true,
        :stdout     => file,
        :namespaces => LXC::CLONE_NEWNET | LXC::CLONE_NEWUTS,
      }
      @container.attach(opts) do
        LXC.run_command('ifconfig eth0')
      end
      file.rewind
      assert_match(/^eth0\s+Link\sencap:Ethernet\s+HWaddr\s/, file.readline)
    ensure
      file.close
      File.unlink(path)
    end
  end

  def test_container_cgroups
    max_mem = @container.cgroup_item('memory.max_usage_in_bytes')
    cur_lim = @container.cgroup_item('memory.limit_in_bytes')
    assert_nothing_raised(LXC::Error) do
      @container.set_cgroup_item('memory.limit_in_bytes', max_mem)
    end
    assert_not_equal(cur_lim, @container.cgroup_item('memory.limit_in_bytes'))
  end

  def test_container_freeze
    @container.freeze
    @container.wait(:frozen, 3)
    assert(@container.init_pid > 1)
    assert(@container.running?)
    assert_equal(:frozen, @container.state)

    @container.unfreeze
    @container.wait(:running, 3)
    assert(@container.init_pid > 1)
    assert(@container.running?)
    assert_equal(:running, @container.state)
  end

  def test_container_clone
    teardown
    assert_nil(@container.init_pid)
    assert(!@container.running?)
    assert_equal(:stopped, @container.state)

    assert_nothing_raised do
      begin
        clone = @container.clone('test_clone')
        clone.start
        clone.stop
      ensure
        clone.destroy
      end
    end
  end

  def test_container_listed
    containers = LXC.list_containers
    assert(containers.length > 0)
    assert(containers.include?(@name))
  end
end
