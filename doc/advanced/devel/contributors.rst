
===================
Contributor's Guide
===================

See below for selection of some of the more common contribution guidelines
maintained directly in `Zeek wiki
<https://github.com/zeek/zeek/wiki#contributors>`_.

General Contribution Process
============================

See https://github.com/zeek/zeek/wiki/Contribution-Guide

Coding Style and Conventions
============================

See https://github.com/zeek/zeek/wiki/Coding-Style-and-Conventions

General Documentation Structure/Process
=======================================

See the :doc:`README </README>` file of https://github.com/zeek/zeek-docs

Documentation Style and Conventions
===================================

See https://github.com/zeek/zeek/wiki/Documentation-Style-and-Conventions

Checking for Memory Errors and Leaks
====================================

See https://github.com/zeek/zeek/wiki/Checking-for-Memory-Errors-and-Leaks

Maintaining long-lived forks of Zeek
====================================

Consistent formatting of the Zeek codebase is enforced automatically by
configurations tracked in the repository. Upstream updates to these
configurations can lead to formatting changes which could cause merge conflicts
for long-lived forks.

Currently the following configuration files in the root directory are used:

- ``.pre-commit-config.yaml``: Configuration for `pre-commit <https://pre-commit.com/>`_.
  We use pre-commit to manage and orchestrate formatters and linters.
- ``.clang-format``: Configuration for `clang-format
  <https://clang.llvm.org/docs/ClangFormat.html>`_ for formatting C++ files.
- ``.style.yapf``: Configuration for `YAPF <https://github.com/google/yapf>`_
  for formatting Python files.
- ``.cmake-format.json``: Configuration for `cmake-format
  <https://github.com/cheshirekow/cmake_format>`_ for formatting CMake files.

With these configuration files present ``pre-commit run --all-files`` will
install all needed formatters and reformat all files in the repository
according to the current configuration.

.. rubric:: Workflow: Zeek ``master`` branch regularly merged into fork

If Zeek's master branch is regularly merged into the fork, merge conflicts can
be resolved once and their resolution is tracked in the repository. Similarly,
we can explicitly reformat the fork once and then merge the upstream branch.

.. code-block:: sh

   ## Get and stage latest versions of configuration files from master.
   git checkout master -- .pre-commit-config.yaml .clang-format .style.yapf .cmake-format.json

   ## Reformat fork according to new configuration.
   pre-commit run -a

   ## Record reformatted state of fork.
   git add -u && git commit -m 'Reformat'

   # Merge in master, resolve merge conflicts as usual.
   git merge master

.. rubric:: Workflow: Fork regularly rebased onto Zeek ``master`` branch

If the target for a rebase has been reformatted individual diff hunks might not
apply cleanly anymore. There are different approaches to work around that. The
approach with the least conflicts is likely to first reformat the fork
according to upstream style without pulling in changes, and only after that
rebase on upstream and resolve potential semantic conflicts.

.. code-block:: sh

   # Create a commit updating the configuration files.
   git checkout master -- .pre-commit-config.yaml .clang-format .style.yapf .cmake-format.json
   git commit -m 'Bump formatter configurations'

   # With a fork branched from upstream at commit FORK_COMMIT, rebase the
   # config update commit 'Bump formatter configurations' to the start of the
   # fork, but do not yet rebase on master (interactively move the last patch
   # to the start of the list of patches).
   git rebase -i FORK_COMMIT

   # Reformat all commits according to configs at the base. We use the '--exec'
   # flag of 'git rebase' to execute pre-commit after applying each patch. If
   # 'git rebase' detects uncommitted changes it stops automatic progress so
   # one can inspect and apply the changes.
   git rebase -i FORK_COMMIT --exec 'pre-commit run --all-files'
   # When this stops, inspect changes and stage them.
   git add -u
   # Continue rebasing. This prompts for a commit message and amends the last
   # patch.
   git rebase --continue

   # The fork is now formatted according to upstream style. Rebase on master,
   # and drop the 'Bump formatter configurations' patch from the list of patches.
   git rebase -i master
