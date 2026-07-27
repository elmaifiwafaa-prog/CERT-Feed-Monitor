import shutil

import pytest


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("tectonic") is None, reason="Tectonic absent : exécuter ce test dans l'image Docker")
def test_tectonic_is_available_for_pdf_integration():
    assert shutil.which("tectonic") is not None
