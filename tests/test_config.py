from cert_watcher.config import load_assets


def test_load_assets_coerces_yaml_version_to_string(tmp_path):
    path = tmp_path / "assets.yaml"
    path.write_text("assets:\n  - id: a\n    name: A\n    owner_team: T\n    contact: {name: Alice, email: a@example.invalid}\n    software:\n      - {vendor: Vendor, product: Product, version: 1.0}\n", encoding="utf-8")
    assert load_assets(path)[0].software[0].version == "1.0"
