#!/bin/sh
# mrk-pypi (docs/44): devpi, plus a one-shot bootstrap that points the root/pypi
# mirror at the panel's PyPI router (MRK_PYPI_UPSTREAM_URL) once devpi answers.
# The bootstrap waits for devpi itself and exits; `init: true` reaps it.
set -eu
sh /opt/mrk/devpi-configure.sh &
exec sh /opt/mrk/devpi-start.sh
