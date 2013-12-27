require 'spec_helper'

describe LXC do

  it '#list_containers should return non-empty list' do
    expect(LXC.list_containers).to_not be_empty
  end

  it '#arch_to_personality should convert 32 bit arch to linux32' do
    expect(LXC.arch_to_personality('x86')).to eq(:linux32)
  end

  it '#arch_to_personality should convert 32 bit arch to linux' do
    expect(LXC.arch_to_personality('x86_64')).to eq(:linux)
  end
end
