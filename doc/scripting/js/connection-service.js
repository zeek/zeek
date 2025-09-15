// connection-service.js
zeek.on('connection_state_remove', { priority: 10 }, (c) => {
  // c.service.push('service-from-js'); only modifies JavaScript array
  c.service = c.service.concat('service-from-js');
});

zeek.hook('Conn::log_policy', (rec, id, filter) => {
  console.log(rec.service);
});
