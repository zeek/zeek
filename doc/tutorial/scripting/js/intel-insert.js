// intel-insert.js
zeek.on('zeek_init', () => {
  let intel_item = {
    indicator: '192.168.0.1',
    indicator_type: 'Intel::ADDR',
    meta: { source: 'some intel source' },
  };

  zeek.invoke('Intel::insert', [intel_item]);
});
