require 'test/unit'
require './lxc'

class TestLXCUndefined < Test::Unit::TestCase
  def setup
    @name = 'test'
    @container = LXC::Container.new(@name)
  end

  def test_container_config_file_name
    config_path = File.join(LXC.default_config_path, @name, 'config')
    assert_equal(config_path, @container.config_file_name)
  end

  def test_container_not_defined
    assert_equal(false, @container.defined?)
  end

  def test_container_init_pid
    assert_equal(nil, @container.init_pid)
  end

  def test_container_not_running
    assert_equal(false, @container.running?)
  end

  def test_container_stopped
    assert_equal(false, @container.running?)
    assert_equal('STOPPED', @container.state)
  end
end
