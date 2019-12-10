===============
Release Process
===============

The intended release schedule is detailed at:
https://blog.zeek.org/2019/04/new-zeek-release-schedule.html

For more background and a visual of how the release branching is managed in
git, see: https://github.com/zeek/zeek/issues/488

Release Checklist
-----------------

Follow all these steps in order to complete a Zeek release.  If this is your
first time making a release, you might expect this to take at least 3 hours to
get everything organized and pushed out, but with familiarity it's more like a
1-2 hour job (good luck!).

* For a patch release (X.Y.Z), verify that the ``release/X.Y`` branch passes
  CI: it runs automatically on every commit to the branch, just make sure
  there's no failures in the latest commit you intend to release.

* Update Zeek’s ``NEWS`` with release notes. The file should contain the most
  important information about the new version, including a summary of major
  changes, especially incompatible ones. It should also point out the major
  changes in submodules.  Also, if ``local.bro`` has changed, point out how to
  adapt a previous one accordingly.

* Finalize and make releases for all git submodules before their parent git
  repo to ensure the parent's submodule points at the correct version.  If a
  submodule has no changes since the last Zeek release, you don't necessarily
  need to make a new release for it (e.g. happens often when making a X.Y.Z
  patch release).  For any submodule that does need a new release, they each
  may have their own release process nuances, but generally::

    $ cd <into/submodule>
    $ update-changes -R v1.2.3
    $ make dist
    $ # Sanity check the resulting tarfile
    $ git push && git push --tags

  .. note::

    It's usually best to use the version of ``update-changes`` linked from
    Zeek's ``master`` branch, not whatever is in the release branch as the
    former may include bug fixes that aren't in the release yet (e.g. if
    those bugs were discovered in the process of making a previous release).

    The ``update-changes`` script can be also re-run for the same version if
    you make last minute tweaks and it will delete the old tags and create new
    ones, but you should only do that if the version hasn't been pushed yet.

  .. note::

    If pushing tags warns of ``release`` already existing, just delete it and
    push again like ``git push --delete origin release && git push --tags``.

* Python projects may additionally have a ``make upload`` target to upload the
  release to PyPI.

* Finalize the Zeek repo

  * Run ``update-changes -R vX.Y.Z`` (e.g. v3.0.0, v3.0.1, v3.1.0, or v3.1.1)
  * At this point, it's a good idea to run ``make dist``, then do a quick
    sanity check of the resulting Zeek tarfile.  E.g. check the new version
    looks right and run the btest suite.
  * Run ``git push && git push --tags``
  * If you're creating an X.Y.0 release, create the ``release/X.Y`` branch
  * Create a supplementary "dev" tag so that ``update-changes`` knows to use a
    pre-release versioning scheme for all subsequent commits to the
    ``release/X.Y`` branch.  For example, after the 3.0.0 release, I
    made/pushed a simple commit that reserved a spot in ``NEWS`` for the
    changes going into a 3.0.1 patch release, updated ``VERSION`` manually to
    ``3.0.1-dev``, and then tagged that commit like::

      $ git tag -a v3.0.1-dev -m "Start of 3.0.1 patch release development"
      $ git push --tags

* Build tarfiles for all new releases: every repo comes with a ``make dist``
  target to generate these.

* Sign tarfiles: see the ``aux/zeek-aux/devel-tools/sign-file`` script as an
  example, but usually boils down to::

    $ for f in *.tar.gz; do gpg --detach-sign -a -u F8CB8019 --openpgp -o $f.asc $f

* Push tarfiles and signatures to webserver::

    $ scp <*.tar.gz*> www.zeek.org:~www/public_html/downloads

* With the tags and tarfiles now pushed out, you can make a dummy commit in the
  ``www`` repo (e.g. add a blank line to download page) and watch to see if the
  downloads page at https://www.zeek.org/download/index.html gets properly
  updated with new release information/links.

* Create a release tag in the ``zeek-docs`` repository (it's also a submodule
  of ``zeek`` in the ``doc/`` dir).  Commands to do that look may look like
  (replace with actual version numbers)::

    $ git tag -a v3.0.1 -m "Docs for Zeek 3.0.1"
    $ git push --tags

  Watch the Read the Docs build and the https://docs.zeek.org page to see that
  it builds and goes live with the new version correctly.

* Create a new GitHub release at https://github.com/zeek/zeek/releases by
  filling in the release notes and uploading the .tar.gz and .tar.gz.asc files.
  Note that this only helps because GitHub’s automatic process for creating
  zip/tarfiles of release tags doesn't include submodules (and that tends to
  confuse users). Hopefully GitHub changes this in the future.

  * Some other notable sub-projects may also upload release files to GitHub.
    For example, Broker does, too: https://github.com/zeek/broker/releases

* Send an announcement email to zeek@zeek.org and zeek-announce@zeek.org.
  Signing the mail can be done like::

    $ gpg --clear-sign -a -u F8CB8019 --openpgp -o <output name>.asc.txt <input file>

Release Candiates
-----------------

Releasing a beta version is roughly the same process as above for the real
release, with the following tweaks:

* ``update-changes`` has a separate option ``-B <version>`` to make a beta
  version.  Using that creates a corresponding ``beta`` tag instead of
  ``release`` (the latter remains untouched). A beta version number must be of
  the form ``vX.Y.Z-rc*`` (e.g. v3.0.0-rc1).

* When doing a Zeek beta, it’s usually best to simply go ahead and make
  releases of all the submodules, except BroControl, first. Often the
  submodules won’t change anymore between beta and release, so that saves some
  time later. If a submodule changes, just do another release for it
  eventually; their version numbers don’t matter much anyway. Once all
  submodules are tagged as releases, prepare betas for Zeek and BroControl.

* Copy the tarfiles into the ``downloads/beta/`` directory, not ``downloads/``.

* Edit the web pages in the ``www`` repository:

  * In ``scripts/make-docs`` add a line ``beta -beta`` to ``VERSIONS``.

  * In ``root/download/index.rst`` enable the (raw HTML) block that shows the
    link to the beta tarfile .
