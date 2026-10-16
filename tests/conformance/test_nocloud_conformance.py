# SPDX-FileCopyrightText: 2026 Mateusz Nowak
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
NoCloud IMDS conformance tests.

Verify that cloud-init's DataSourceNoCloudNet, configured exactly as a
Proxmox VM would be (SMBIOS serial ``ds=nocloud-net;s=<url>/nocloud/;h=...``),
can crawl our /nocloud/ endpoint and parse what we serve, including
user-data rendered from a (fake) OpenBao KV v2 secret set.
"""

from unittest import mock

import pytest

from cloudinit import helpers
from cloudinit.sources import DataSourceNoCloud as nocloud_ds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_datasource(serial: str, tmp_path) -> nocloud_ds.DataSourceNoCloudNet:
    """Return a DataSourceNoCloudNet that sees ``serial`` as its DMI serial."""
    distro = mock.MagicMock()
    distro.get_tmp_exec_path = str(tmp_path)
    paths = helpers.Paths(
        {"run_dir": str(tmp_path), "seed_dir": str(tmp_path / "seed")}
    )
    ds = nocloud_ds.DataSourceNoCloudNet(
        sys_cfg={}, distro=distro, paths=paths
    )
    # No cidata disk on the test host.
    ds._get_devices = lambda label: []
    ds._serial = serial
    return ds


def _get_data(ds) -> bool:
    """Run ds._get_data() with DMI and the kernel cmdline mocked."""
    with mock.patch.object(
        nocloud_ds.dmi,
        "read_dmi_data",
        side_effect=lambda key: ds._serial
        if key == "system-serial-number"
        else None,
    ), mock.patch.object(nocloud_ds.util, "get_cmdline", return_value=""):
        return ds._get_data()


def _serial(base_url: str, suffix: str = "/nocloud/", hostname: str = "") -> str:
    serial = f"ds=nocloud-net;s={base_url}{suffix}"
    if hostname:
        serial += f";h={hostname}"
    return serial


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ds(nocloud_imds_server, tmp_path):
    """DataSourceNoCloudNet crawled from the conformance harness."""
    ds = _make_datasource(_serial(nocloud_imds_server["base_url"]), tmp_path)
    assert _get_data(ds) is True
    return ds


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNoCloudConformance:
    """End-to-end conformance: DataSourceNoCloudNet against /nocloud/."""

    def test_get_data_returns_true(self, ds):
        assert ds.seed is not None

    @pytest.mark.parametrize("suffix", ["/nocloud/", "/nocloud"])
    def test_seed_url_with_and_without_trailing_slash(
        self, nocloud_imds_server, tmp_path, suffix
    ):
        """cloud-init (>= 23.1) appends a missing '/' to the seed URL."""
        ds = _make_datasource(
            _serial(nocloud_imds_server["base_url"], suffix), tmp_path
        )
        assert _get_data(ds) is True
        assert ds.get_instance_id() == str(nocloud_imds_server["vmid"])

    def test_instance_id(self, ds, nocloud_imds_server):
        """instance-id falls back to the VMID when smbios1 has no uuid."""
        assert ds.get_instance_id() == str(nocloud_imds_server["vmid"])

    def test_local_hostname(self, ds, nocloud_imds_server):
        assert ds.metadata["local-hostname"] == nocloud_imds_server["vm_name"]

    def test_hostname_from_serial_overrides(self, nocloud_imds_server, tmp_path):
        """h= in the SMBIOS serial wins over meta-data local-hostname."""
        ds = _make_datasource(
            _serial(nocloud_imds_server["base_url"], hostname="from-serial"),
            tmp_path,
        )
        assert _get_data(ds) is True
        assert ds.metadata["local-hostname"] == "from-serial"

    def test_rendered_user_data(self, ds, nocloud_imds_server):
        """The secrets= template is served with placeholders substituted."""
        ud = ds.userdata_raw
        if isinstance(ud, bytes):
            ud = ud.decode()
        assert ud == nocloud_imds_server["user_data"]
        assert "{{" not in ud

    def test_vendor_data_empty(self, ds):
        assert not ds.vendordata_raw

    def test_network_config_dhcp_by_mac(self, ds, nocloud_imds_server):
        """Without a Notes network-config block, every NIC gets DHCPv4."""
        nc = ds.network_config
        assert nc["version"] == 2
        assert len(nc["ethernets"]) == 1
        eth = nc["ethernets"]["net0"]
        assert eth["match"]["macaddress"] == nocloud_imds_server["mac"]
        assert eth["dhcp4"] is True
