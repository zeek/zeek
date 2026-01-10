:tocdepth: 3

builtin-plugins/Zeek_JavaScript/__load__.zeek
=============================================
.. zeek:namespace:: JavaScript


:Namespace: JavaScript

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================= =====================================================================
:zeek:id:`JavaScript::exit_on_uncaught_exceptions`: :zeek:type:`bool` :zeek:attr:`&redef` Node.js default behavior is to exit a process on uncaught exceptions.
:zeek:id:`JavaScript::files`: :zeek:type:`vector` :zeek:attr:`&redef`                     Vector of filenames to compile/execute after the bootstrap file.
:zeek:id:`JavaScript::initial_heap_size_in_bytes`: :zeek:type:`count` :zeek:attr:`&redef` Be very conservative.
:zeek:id:`JavaScript::main_script_source`: :zeek:type:`string` :zeek:attr:`&redef`        The Javascript code executed for bootstrapping.
:zeek:id:`JavaScript::maximum_heap_size_in_bytes`: :zeek:type:`count` :zeek:attr:`&redef`
:zeek:id:`JavaScript::owns_node_inspector`: :zeek:type:`bool` :zeek:attr:`&redef`         If set to T, installs a SIGUSR1 handler and thread to
                                                                                          start the Node.js / V8 inspector.
:zeek:id:`JavaScript::owns_process_state`: :zeek:type:`bool` :zeek:attr:`&redef`          Allows to change process state (uid, title, cwd, ...).
:zeek:id:`JavaScript::thread_pool_size`: :zeek:type:`count` :zeek:attr:`&redef`
========================================================================================= =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: JavaScript::exit_on_uncaught_exceptions
   :source-code: builtin-plugins/Zeek_JavaScript/__load__.zeek 62 62

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Node.js default behavior is to exit a process on uncaught exceptions.
   Specifically exceptions in timer callbacks are problematic as a throwing
   timer callback may break subsequently scheduled timers.

   Set this to F in order to just keep going when errors happen. Note,
   if you see any Uncaught errors, this likely means the Javascript
   state is corrupt.

.. zeek:id:: JavaScript::files
   :source-code: builtin-plugins/Zeek_JavaScript/__load__.zeek 48 48

   :Type: :zeek:type:`vector` of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         []


   Vector of filenames to compile/execute after the bootstrap file.

.. zeek:id:: JavaScript::initial_heap_size_in_bytes
   :source-code: builtin-plugins/Zeek_JavaScript/__load__.zeek 51 51

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``67108864``

   Be very conservative.

.. zeek:id:: JavaScript::main_script_source
   :source-code: builtin-plugins/Zeek_JavaScript/__load__.zeek 12 12

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"const module_mod = require('module')\x0aconst publicRequire = module_mod.createRequire(process.cwd() + '/');\x0aglobalThis.require = publicRequire;\x0a\x0aglobalThis.zeek_javascript_init = async () => {\x0a  const zeek = process._linkedBinding('zeekjs').zeek;\x0a  // Helper for zeek record rendering.\x0a  zeek.flatten = (obj, prefix, res) => {\x0a    res = res || {}\x0a    for (const k in obj) {\x0a      const nk = prefix ? `${prefix}.${k}` : k\x0a      const v = obj[k]\x0a\x0a      // Recurse for objects, unless it's actually an array, or has a\x0a      // custom toJSON() method (which is true for the port objects).\x0a      if (v !== null && typeof(v) == 'object' && !Array.isArray(v) && !('toJSON' in v)) {\x0a        zeek.flatten(v, nk, res)\x0a      } else {\x0a        res[nk] = v\x0a      }\x0a    }\x0a    return res\x0a  }\x0a\x0a  const m = new module_mod();\x0a  // Compile a new module that imports all .js files found using import().\x0a  //\x0a  // https://stackoverflow.com/a/17585470/9044112\x0a  return m._compile('const ps = []; zeek.__zeek_javascript_files.forEach((fn) => { ps.push(import(fn)); }); return Promise.all(ps);', process.cwd() + '/');\x0a};\x0a// Add a global zeek object from the linked zeekjs binding\x0aglobalThis.zeek = process._linkedBinding('zeekjs').zeek;\x0a"``

   The Javascript code executed for bootstrapping.
   This comes fairly straight from the embedding guide to support using
   require() with filesystem paths in the process working directory.

   https://docs.w3cub.com/node~14_lts/embedding


.. zeek:id:: JavaScript::maximum_heap_size_in_bytes
   :source-code: builtin-plugins/Zeek_JavaScript/__load__.zeek 52 52

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``134217728``


.. zeek:id:: JavaScript::owns_node_inspector
   :source-code: builtin-plugins/Zeek_JavaScript/__load__.zeek 75 75

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If set to T, installs a SIGUSR1 handler and thread to
   start the Node.js / V8 inspector.

   See Node.js EnvironmentFlags API documentation for details.
   https://github.com/nodejs/node/blob/v22.11.0/src/node.h#L631

.. zeek:id:: JavaScript::owns_process_state
   :source-code: builtin-plugins/Zeek_JavaScript/__load__.zeek 68 68

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Allows to change process state (uid, title, cwd, ...).

   See Node.js EnvironmentFlags API documentation for details.
   https://github.com/nodejs/node/blob/v22.11.0/src/node.h#L627

.. zeek:id:: JavaScript::thread_pool_size
   :source-code: builtin-plugins/Zeek_JavaScript/__load__.zeek 53 53

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``4``



