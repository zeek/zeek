## Install mermaid-cli

    npm install @mermaid-js/mermaid-cli

## Apparmor Errors

If running ``mmdc`` fails under Linux (e.g. with Ubuntu 24.04) with apparmor
errors about ``userns_create`` in the ``demsg`` output, put the following into
``/etc/apparmor.d/chrome-headless``

    # This profile allows everything and only exists to give the
    # application a name instead of having the label "unconfined"
    abi <abi/4.0>,
    include <tunables/global>

    profile chrome /home/awelzel/.cache/puppeteer/**/chrome-headless-shell flags=(unconfined) {
      userns,

      # Site-specific additions and overrides. See local/README for details.
      include if exists <local/chrome>
    }


See also: https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md#option-2_a-safer-way
