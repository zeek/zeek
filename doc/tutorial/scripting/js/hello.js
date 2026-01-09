// hello.js
zeek.on('zeek_init', () => {
  let version = zeek.invoke('zeek_version');
  console.log(`Hello, Zeek ${version}!`);
});
