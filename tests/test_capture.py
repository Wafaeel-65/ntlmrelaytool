def test_start_capture():
    from src.modules.capture.responder import Responder

    responder = Responder()
    responder.start_capture()
    assert responder.is_capturing is True
    responder.stop_capture()

def test_stop_capture():
    from src.modules.capture.responder import Responder

    responder = Responder()
    responder.start_capture()
    responder.stop_capture()
    assert responder.is_capturing is False

def test_parse_hashes():
    from src.modules.capture.parser import parse_hashes

    raw_data = "user:hash"
    expected_output = {"username": "user", "hash": "hash"}
    assert parse_hashes(raw_data) == expected_output

def test_parse_hashes_empty():
    from src.modules.capture.parser import parse_hashes

    raw_data = ""
    expected_output = {}
    assert parse_hashes(raw_data) == expected_output