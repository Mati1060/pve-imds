#!/bin/sh
# postinst script for pve-imds

set -e

case "$1" in
    configure)

        # Group that may read the OpenBao token file used for templated
        # user-data (see secrets.token_file). The service unit references it,
        # so it must exist before the service is (re)started below.
        if ! getent group pve-imds-token >/dev/null; then
            addgroup --system pve-imds-token >/dev/null
        fi

        # The following line should be removed in trixie or trixie+1
        deb-systemd-helper unmask 'pve-imds.service' >/dev/null || true

        # was-enabled defaults to true, so new installations run enable.
        if deb-systemd-helper --quiet was-enabled 'pve-imds.service'; then
            # Enables the unit on first installation, creates new
            # symlinks on upgrades if the unit file has changed.
            deb-systemd-helper enable 'pve-imds.service' >/dev/null || true
        else
            # Update the statefile to add new symlinks (if any), which need to be
            # cleaned up on purge. Also remove old symlinks.
            deb-systemd-helper update-state 'pve-imds.service' >/dev/null || true
        fi

        if [ -d /run/systemd/system ]; then
            systemctl --system daemon-reload >/dev/null || true
            if [ -n "$2" ]; then
                _dh_action=restart
            else
                _dh_action=start
            fi
            deb-systemd-invoke $_dh_action 'pve-imds.service' >/dev/null || true
        fi
    ;;

    abort-upgrade|abort-remove|abort-deconfigure)
    ;;

    *)
        echo "postinst called with unknown argument \`$1'" >&2
        exit 1
    ;;
esac

exit 0
