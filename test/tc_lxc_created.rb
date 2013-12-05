require 'test/unit'
require './lxc'

LXC_TEMPLATE   = 'ubuntu'
CONTAINER_NAME = 'test'
CLONE_NAME     = 'test_clone'

class TestLXCCreated < Test::Unit::TestCase
  def setup
    if Process::Sys::geteuid != 0
      raise 'This test must be ran as root'
    end
    @name = CONTAINER_NAME
    @container = LXC::Container.new(@name)
    @container.create(LXC_TEMPLATE) unless @container.defined?
  end

  def test_container_defined
    assert(@container.defined?)
  end

  def test_container_name
    assert_equal(@name, @container.name)
    assert_equal(@name, @container.config_item('lxc.utsname'))
  end

  def test_container_configuration
    capdrop = @container.config_item('lxc.cap.drop')
    @container.clear_config_item('lxc.cap.drop')
    @container.set_config_item('lxc.cap.drop', capdrop[0...-1])
    @container.set_config_item('lxc.cap.drop', capdrop[-1])
    @container.save_config
    assert_equal(capdrop, @container.config_item('lxc.cap.drop'))
  end

  def test_container_networking
    assert(@container.keys('lxc.network.0').include?('name'))
    assert_match(/^00:16:3e:/, @container.config_item('lxc.network.0.hwaddr'))
  end
end
