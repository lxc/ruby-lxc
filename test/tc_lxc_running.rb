require 'test/unit'
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
    @container.stop
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
    @container.attach(:wait => true,
                      :namespaces => LXC::CLONE_NEWNET | LXC::CLONE_NEWUTS) do
      LXC.run_command(['ifconfig', 'eth0'])
    end
  end
end
