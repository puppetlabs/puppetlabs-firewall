describe 'formatting in README.markdown' do
  it 'should not contain badly formatted heading markers' do
    content = File.read('README.markdown')
    expect(content).to_not match /^#+[^# ]/
  end
end
