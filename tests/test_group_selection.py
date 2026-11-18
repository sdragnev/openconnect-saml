"""Gateway answers the init request with a group list instead of SSO.

Happens when the ``<group-select>`` we send is not a valid tunnel group
(e.g. after the admins renamed the groups): the ASA falls back to its
default group and returns a ``<select name="group_list">`` form with no
``sso-v2-login``. We must pick a valid group and redo the init request.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from lxml import etree

from openconnect_saml.authenticator import (
    AuthCompleteResponse,
    AuthenticationError,
    Authenticator,
    AuthGroupSelectionError,
    AuthRequestResponse,
    GroupSelectResponse,
    _create_auth_init_request,
    parse_response,
)

GROUP_LIST_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg">
<tunnel-group>defaultLDAP</tunnel-group>
<aggauth-handle>1234567890123456789</aggauth-handle>
<auth-method>single-sign-on-v2</auth-method>
<group-alias>1 Employees</group-alias>
<config-hash>1000000000000</config-hash>
</opaque>
<auth id="main">
<form>
<input type="text" name="username" label="Username:"></input>
<input type="password" name="password" label="Password:"></input>
<select name="group_list" label="GROUP:">
<option selected="true">1 Employees</option>
<option>2 Contractors</option>
<option>3 Engineering</option>
<option>4 Q.A.</option>
</select>
</form>
</auth>
</config-auth>
"""

SSO_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg"><tunnel-group>SAML</tunnel-group></opaque>
<auth id="main">
<title>Login</title>
<message>Please complete the authentication process.</message>
<sso-v2-login>https://idp.example.com/login</sso-v2-login>
<sso-v2-login-final>https://vpn.example.com/done</sso-v2-login-final>
<sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
</auth>
</config-auth>
"""

GROUPS = ["1 Employees", "2 Contractors", "3 Engineering", "4 Q.A."]


def _resp(content):
    r = MagicMock()
    r.content = content
    r.status_code = 200
    r.url = "https://vpn.example.com/"
    r.raise_for_status.return_value = None
    return r


def _sent_group(call):
    body = call.args[1]
    return etree.fromstring(body).findtext("group-select")


def _make_auth(name, responses, group_selector=None):
    host = MagicMock()
    host.vpn_url = "https://vpn.example.com/"
    host.name = name
    with patch("openconnect_saml.authenticator.create_http_session"):
        auth = Authenticator(host, version="4.7.00136", group_selector=group_selector)
    auth.session = MagicMock()
    auth.session.post.side_effect = [_resp(c) for c in responses]
    auth._detect_authentication_target_url = MagicMock()
    return auth


def _run(auth):
    with (
        patch.object(auth, "_authenticate_in_browser", AsyncMock(return_value="sso-token")),
        patch.object(auth, "_complete_authentication") as complete,
    ):
        complete.return_value = AuthCompleteResponse("success", "", "tok", "hash")
        return asyncio.run(auth.authenticate("shown")), complete


def test_parse_group_list_response():
    resp = parse_response(_resp(GROUP_LIST_XML))
    assert isinstance(resp, GroupSelectResponse)
    assert resp.groups == GROUPS
    assert resp.selected == "1 Employees"


def test_sso_response_still_parsed():
    assert isinstance(parse_response(_resp(SSO_XML)), AuthRequestResponse)


def test_option_value_attribute_preferred():
    xml = GROUP_LIST_XML.replace(
        b"<option>3 Engineering</option>", b'<option value="eng">3 Engineering</option>'
    )
    assert "eng" in parse_response(_resp(xml)).groups


def test_init_request_group_override():
    host = MagicMock()
    host.name = "rcc"
    body = _create_auth_init_request(host, "https://vpn.example.com/", "4.7", group="3 Engineering")
    assert etree.fromstring(body).findtext("group-select") == "3 Engineering"


def test_valid_authgroup_reinits_with_matching_group():
    # Server only accepts the canonical spelling; we match case-insensitively
    # against the offered list and resend the canonical name.
    auth = _make_auth("3 engineering", [GROUP_LIST_XML, SSO_XML])
    result, complete = _run(auth)
    assert result.session_token == "tok"
    calls = auth.session.post.call_args_list
    assert [_sent_group(c) for c in calls] == ["3 engineering", "3 Engineering"]


def test_unknown_group_prompts_then_reinits():
    selector = MagicMock(return_value="4 Q.A.")
    auth = _make_auth("rcc", [GROUP_LIST_XML, SSO_XML], group_selector=selector)
    _run(auth)
    selector.assert_called_once_with(GROUPS, "1 Employees", "rcc")
    assert [_sent_group(c) for c in auth.session.post.call_args_list] == ["rcc", "4 Q.A."]


def test_unknown_group_without_selector_lists_groups():
    auth = _make_auth("rcc", [GROUP_LIST_XML])
    with pytest.raises(AuthGroupSelectionError) as exc:
        _run(auth)
    msg = str(exc.value)
    assert "'rcc'" in msg and "'3 Engineering'" in msg and "--authgroup" in msg
    assert isinstance(exc.value, AuthenticationError)


def test_selected_group_without_sso_raises_instead_of_looping():
    selector = MagicMock(return_value="1 Employees")
    # Server keeps returning the username/password form for "1 Employees".
    auth = _make_auth("rcc", [GROUP_LIST_XML, GROUP_LIST_XML], group_selector=selector)
    with pytest.raises(AuthGroupSelectionError, match="does not offer SAML"):
        _run(auth)
    assert auth.session.post.call_count == 2
