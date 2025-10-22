// global-vars.js
const timeouts = zeek.global_vars['Conn::analyzer_inactivity_timeouts'];

// Similar to redef.
timeouts['AllAnalyzers::ANALYZER_ANALYZER_SSH'] = 42.0;

zeek.on('zeek_init', () => {
  console.log('js', timeouts);
});
