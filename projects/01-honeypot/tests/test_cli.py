from honeypot.cli import _parse_ports, build_parser


def test_parse_ports_default():
    assert 22 in _parse_ports(None)
    assert 80 in _parse_ports(None)


def test_parse_ports_explicit():
    assert _parse_ports("22,80, 443") == [22, 80, 443]


def test_parse_ports_empty_string():
    assert _parse_ports("") == _parse_ports(None)


def test_parser_defaults():
    args = build_parser().parse_args([])
    assert args.dashboard_port == 8080
    assert args.host == "0.0.0.0"
    assert args.no_dashboard is False


def test_parser_overrides():
    args = build_parser().parse_args(
        ["--ports", "2222", "--dashboard-port", "9000", "--no-sensor"]
    )
    assert args.ports == "2222"
    assert args.dashboard_port == 9000
    assert args.no_sensor is True
