require 'test/unit'
require 'tempfile'
require './lxc'

LXC_TEMPLATE   = 'ubuntu'
CONTAINER_NAME = 'test'
CLONE_NAME     = 'test_clone'

class TestLXCRunning < Test::Unit::TestCase
  def setup
    if Process::Sys::geteuid != 0
      raise 'This test must be ran as root'
    end
    @name = CONTAINER_NAME
    @container = LXC::Container.new(@name)
    @container.create(LXC_TEMPLATE) unless @container.defined?
    @container.start
  end

  def teardown
    @container.shutdown(3)
    if @container.running?
      @container.stop
      @container.wait('STOPPED', 3)
    end
  end

  def test_container_running
    @container.wait('RUNNING', 3)
    assert(@container.init_pid > 1)
    assert(@container.running?)
    assert_equal('RUNNING', @container.state)
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
    assert_not_nil(@container.set_cgroup_item('memory.limit_in_bytes', max_mem))
    assert_not_equal(cur_lim, @container.cgroup_item('memory.limit_in_bytes'))
  end

  def test_container_freeze
    @container.freeze
    @container.wait('FROZEN', 3)
    assert(@container.init_pid > 1)
    assert(@container.running?)
    assert_equal('FROZEN', @container.state)

    @container.unfreeze
    @container.wait('RUNNING', 3)
    assert(@container.init_pid > 1)
    assert(@container.running?)
    assert_equal('RUNNING', @container.state)
  end

  def test_container_clone
    teardown
    assert_nil(@container.init_pid)
    assert(!@container.running?)
    assert_equal('STOPPED', @container.state)

    assert_nothing_raised do
      begin
        clone = @container.clone(CLONE_NAME)
        clone.start
        clone.stop
      ensure
        clone.destroy
      end
    end
  end
end
