require 'spec_helper'

describe LXC::Container do

  it '#defined should be true for an existing container' do
    expect(container.defined?).to be_true
  end

  it '#name should return container name' do
    expect(container.name).to eq(container_name)
  end

  it '#name should be same as utsname config parameter' do
    expect(container.name).to eq(container.config_item('lxc.utsname'))
  end

  it '#config_item should allow setting and retrival of container specific config' do
    capdrop = container.config_item('lxc.cap.drop')
    container.clear_config_item('lxc.cap.drop')
    container.set_config_item('lxc.cap.drop', capdrop[0...-1])
    container.set_config_item('lxc.cap.drop', capdrop[-1])
    container.save_config
    expect(container.config_item('lxc.cap.drop')).to eq(capdrop)
  end

  it '#keys should allow retrival of network information' do
    expect(container.keys('lxc.network.0')).to include('name')
    expect(container.config_item('lxc.network.0.hwaddr')).to match(/^00:16:3e:/)
  end

  it '#rename should allow renaming existing container' do
    new_name = "renamed_#{container_name}"
    renamed = container.rename(new_name)
    expect(renamed.name).to eq(new_name)
    rerenamed = renamed.rename(container_name)
    expect(rerenamed.name).to eq(container_name)
  end
end
