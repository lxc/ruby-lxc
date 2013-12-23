$:.unshift File.expand_path(File.join(File.dirname(__FILE__), 'lib'))

require 'test/unit'
require 'lxc'

class TestLXCCreated < Test::Unit::TestCase
  def setup
    if Process::Sys::geteuid != 0
      raise 'This test must be ran as root'
    end
    @name = 'test'
    @container = LXC::Container.new(@name)
    @container.create('ubuntu') unless @container.defined?
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

  def test_container_rename
    new_name = "renamed_#{@name}"
    renamed = @container.rename(new_name)
    assert_equal(new_name, renamed.name)
    rerenamed = renamed.rename(@name)
    assert_equal(@name, rerenamed.name)
  end
end
