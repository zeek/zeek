// zeek-as.js
zeek.on('zeek_init', () => {
  try {
    // This throws because type_name takes an any parameter
    zeek.invoke('type_name', ['192.168.0.0/16']);
  } catch (e) {
    console.error(`error: ${e}`);
  }

  // Explicit conversion of string to addr type.
  let type_string = zeek.invoke('type_name', [zeek.as('subnet', '192.168.0.0/16')]);
  console.log(`good: type_name is ${type_string}`);
});
