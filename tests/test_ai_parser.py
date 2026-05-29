from shield.ai_analyzer import AIAnalyzer


def test_parses_plain_json():
    raw = '{"blocks":[{"ip":"1.2.3.4","reason":"bf","confidence":0.9}]}'
    out = AIAnalyzer._parse_response(raw)
    assert out and out["blocks"][0]["ip"] == "1.2.3.4"


def test_parses_fenced_json():
    raw = "```json\n{\"blocks\": []}\n```"
    out = AIAnalyzer._parse_response(raw)
    assert out == {"blocks": []}


def test_parses_embedded_json():
    raw = "Here is the analysis:\n{\"blocks\": [{\"ip\":\"9.9.9.9\",\"confidence\":0.8}]}\nthanks"
    out = AIAnalyzer._parse_response(raw)
    assert out and out["blocks"][0]["ip"] == "9.9.9.9"


def test_returns_none_on_garbage():
    assert AIAnalyzer._parse_response("totally not json") is None
