use crate::{invalid, store::random_id};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
    pub private_key_password: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    challenge_id: String,
    username: Option<String>,
    password: Option<String>,
    private_key_password: Option<String>,
    response: Option<String>,
}
struct Action {
    id: String,
    kind: &'static str,
    prompt: String,
    url: Option<String>,
    opaque: String,
}
pub struct Authentication {
    pub state: String,
    pub reason: String,
    pub session: String,
    pub expires_at: Option<u64>,
    pub credentials: Credentials,
    pub remembered: bool,
    action: Option<Action>,
    automatic: bool,
    connected_before: bool,
    dynamic_ready: bool,
    dynamic_response: Option<Vec<String>>,
}
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn checked(value: &str) -> io::Result<()> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(invalid(
            "authentication value exceeds its limit or contains controls",
        ));
    }
    Ok(())
}
fn quote(value: &str) -> String {
    format!(
        "\"{}\"",
        if value.is_empty() {
            "[[BLANK]]".to_owned()
        } else {
            value.replace('\\', "\\\\").replace('"', "\\\"")
        }
    )
}
impl Authentication {
    pub fn new(credentials: Credentials, remembered: bool) -> io::Result<Self> {
        for value in [
            &credentials.username,
            &credentials.password,
            &credentials.private_key_password,
        ]
        .into_iter()
        .flatten()
        {
            checked(value)?;
        }
        Ok(Self {
            state: "connecting".into(),
            reason: "starting".into(),
            session: random_id()?,
            expires_at: None,
            credentials,
            remembered,
            action: None,
            automatic: true,
            connected_before: false,
            dynamic_ready: false,
            dynamic_response: None,
        })
    }
    pub fn describe(&self) -> Value {
        json!({"authentication":self.state,"reason":self.reason,"requires_input":self.action.is_some(),"action":self.action.as_ref().map(|a|a.kind),"expires_at":self.expires_at,"remembered":self.remembered})
    }
    pub fn action(&self) -> Value {
        match &self.action {
            Some(a) => {
                json!({"authentication":self.state,"challenge_id":a.id,"method":a.kind,"prompt":a.prompt,"url":a.url,"expires_at":self.expires_at,"remembered":self.remembered})
            }
            None => self.describe(),
        }
    }
    pub fn fail(&mut self, reason: &str) {
        self.state = if !reason.starts_with("authentication") {
            "unknown"
        } else if self.connected_before || reason == "authentication_expired" {
            "expired"
        } else {
            "failed"
        }
        .into();
        self.reason = reason.into();
        self.action = None;
        self.expires_at = None;
        self.automatic = false;
        self.dynamic_ready = false;
        self.dynamic_response = None;
    }
    pub fn forget(&mut self) {
        self.dynamic_ready = false;
        self.dynamic_response = None;
        self.credentials = Credentials::default();
        self.remembered = false;
        self.automatic = false;
    }
    pub fn expire(&mut self) -> bool {
        if self.expires_at.is_some_and(|deadline| now() >= deadline) {
            self.fail("authentication_expired");
            return true;
        }
        false
    }
    fn require(
        &mut self,
        kind: &'static str,
        prompt: &str,
        url: Option<String>,
        opaque: String,
    ) -> io::Result<()> {
        if prompt.len() > 1024 || prompt.chars().any(char::is_control) {
            return Err(invalid("invalid native authentication challenge"));
        }
        if self.action.as_ref().is_some_and(|a| {
            a.kind == kind && a.prompt == prompt && a.url == url && a.opaque == opaque
        }) {
            return Ok(());
        }
        if self.state == "authenticated" {
            self.session = random_id()?;
        }
        self.action = Some(Action {
            id: random_id()?,
            kind,
            prompt: prompt.to_owned(),
            url,
            opaque,
        });
        self.state = match kind {
            "web" => "browser_required",
            "password" | "private_key" => "credentials_required",
            _ => "challenge_required",
        }
        .into();
        self.reason = "operator_input_required".into();
        self.expires_at.get_or_insert(now() + 300);
        Ok(())
    }
    pub fn receive(&mut self, line: &str) -> io::Result<Vec<String>> {
        if line.len() > 65536 || line.contains('\0') {
            return Err(invalid("native management event exceeds its limit"));
        }
        if line.starts_with(">PASSWORD:Verification Failed:") {
            if self.state == "authenticated" {
                self.session = random_id()?;
            }
            self.automatic = false;
            self.dynamic_ready = false;
            self.dynamic_response = None;
            if let Some(start) = line.find("CRV1:") {
                let text = line[start..].trim_end_matches([']', '\'', ' ']);
                let parts: Vec<_> = text.splitn(5, ':').collect();
                if parts.len() != 5 || parts[2].is_empty() {
                    return Err(invalid("invalid native dynamic challenge"));
                }
                if parts[1]
                    .split(',')
                    .any(|flag| !matches!(flag, "" | "R" | "E"))
                {
                    return Err(invalid("native challenge flags are unsupported"));
                }
                checked(parts[2])?;
                let username = STANDARD
                    .decode(parts[3])
                    .ok()
                    .and_then(|v| String::from_utf8(v).ok())
                    .ok_or_else(|| invalid("invalid native dynamic identity"))?;
                checked(&username)?;
                self.credentials.username = Some(username);
                self.require("dynamic", parts[4], None, parts[2].into())?;
            } else {
                self.fail("authentication_rejected");
            }
        } else if line.starts_with(">PASSWORD:Need 'Private Key'") {
            self.require("private_key", "Private key password", None, String::new())?;
            if self.automatic
                && let Some(password) = &self.credentials.private_key_password
            {
                let result = vec![format!("password \"Private Key\" {}", quote(password))];
                self.action = None;
                self.expires_at = None;
                self.state = "authenticating".into();
                self.reason = "remembered_credentials_submitted".into();
                return Ok(result);
            }
        } else if line.starts_with(">PASSWORD:Need 'Auth'") {
            if let Some(commands) = self.dynamic_response.take() {
                self.dynamic_ready = false;
                return Ok(commands);
            }
            if self.action.as_ref().is_some_and(|a| a.kind == "dynamic") {
                self.dynamic_ready = true;
                return Ok(Vec::new());
            }
            if let Some((_, challenge)) = line.split_once(" SC:") {
                let (echo, prompt) = challenge
                    .split_once(',')
                    .ok_or_else(|| invalid("invalid native static challenge"))?;
                if !matches!(echo, "0" | "1") {
                    return Err(invalid("invalid native static challenge"));
                }
                self.require("static", prompt, None, String::new())?;
            } else {
                self.require("password", "VPN username and password", None, String::new())?;
                if self.automatic
                    && let (Some(user), Some(password)) =
                        (&self.credentials.username, &self.credentials.password)
                {
                    let result = vec![
                        format!("username \"Auth\" {}", quote(user)),
                        format!("password \"Auth\" {}", quote(password)),
                    ];
                    self.action = None;
                    self.expires_at = None;
                    self.state = "authenticating".into();
                    self.reason = "remembered_credentials_submitted".into();
                    return Ok(result);
                }
            }
        } else if let Some(text) = line.strip_prefix(">INFOMSG:") {
            if let Some(challenge) = text.strip_prefix("CR_TEXT:") {
                let (flags, prompt) = challenge
                    .split_once(':')
                    .ok_or_else(|| invalid("invalid native text challenge"))?;
                if flags.split(',').any(|flag| !matches!(flag, "" | "R" | "E")) {
                    return Err(invalid("native challenge flags are unsupported"));
                }
                self.require("text", prompt, None, String::new())?;
            } else if text.starts_with("WEB_AUTH:") || text.starts_with("OPEN_URL:") {
                if text.len() > 1024 {
                    return Err(invalid("native web authentication URL exceeds its limit"));
                }
                let url = if let Some(rest) = text.strip_prefix("WEB_AUTH:") {
                    let (flags, url) = rest
                        .split_once(':')
                        .ok_or_else(|| invalid("invalid native web authentication"))?;
                    if flags
                        .split(',')
                        .any(|flag| !matches!(flag, "" | "external" | "hidden"))
                    {
                        return Err(invalid("native web authentication flags are unsupported"));
                    }
                    url
                } else {
                    text.strip_prefix("OPEN_URL:").unwrap()
                };
                let parsed = url::Url::parse(url)
                    .map_err(|_| invalid("invalid native web authentication URL"))?;
                if parsed.scheme() != "https"
                    || parsed.host_str().is_none()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || url.chars().any(char::is_control)
                {
                    return Err(invalid(
                        "native web authentication requires HTTPS without URL credentials",
                    ));
                }
                self.require(
                    "web",
                    "Open this URL in your browser",
                    Some(url.to_owned()),
                    String::new(),
                )?;
            }
        } else if let Some(state) = line.strip_prefix(">STATE:") {
            let fields: Vec<_> = state.split(',').collect();
            match fields.get(1).copied() {
                Some("CONNECTED") => {
                    self.state = "authenticated".into();
                    self.reason = "native_session_established".into();
                    self.action = None;
                    self.expires_at = None;
                    self.connected_before = true;
                    self.dynamic_ready = false;
                    self.dynamic_response = None;
                }
                Some("RECONNECTING" | "EXITING") => {
                    if self.state == "authenticated" {
                        self.session = random_id()?;
                    }
                    if fields.get(2).is_some_and(|s| s.contains("auth-failure")) {
                        if self.action.as_ref().is_none_or(|a| a.kind != "dynamic")
                            && self.dynamic_response.is_none()
                        {
                            self.fail("authentication_expired");
                        }
                    } else if self.action.is_none() {
                        self.state = "connecting".into();
                        self.reason = match fields.get(2).copied() {
                            Some("tls-error") => "tls_handshake_failed",
                            _ => "native_reconnecting",
                        }
                        .into();
                    }
                }
                Some("AUTH_PENDING") => {
                    if self.state == "authenticated" {
                        self.session = random_id()?;
                    }
                    if let Some(timeout) = fields
                        .get(2)
                        .and_then(|s| s.strip_prefix("timeout "))
                        .and_then(|s| s.parse::<u64>().ok())
                    {
                        self.expires_at = Some(now() + timeout.min(3600));
                    }
                    if self.action.is_none() {
                        self.state = "authenticating".into();
                        self.reason = "server_authentication_pending".into();
                    }
                }
                _ => {}
            }
        }
        Ok(Vec::new())
    }
    pub fn submit(&mut self, value: &Value, remember: bool) -> io::Result<Vec<String>> {
        if self.expire() {
            return Err(invalid(
                "authentication challenge expired; restart the applied connection",
            ));
        }
        let reply: Reply = serde_json::from_value(value.clone())
            .map_err(|_| invalid("invalid authentication input"))?;
        for value in [
            &reply.username,
            &reply.password,
            &reply.private_key_password,
            &reply.response,
        ]
        .into_iter()
        .flatten()
        {
            checked(value)?;
        }
        let action = self
            .action
            .as_ref()
            .filter(|a| a.id == reply.challenge_id)
            .ok_or_else(|| invalid("authentication challenge changed or was already answered"))?;
        let matching_fields = match action.kind {
            "private_key" => {
                reply.username.is_none() && reply.password.is_none() && reply.response.is_none()
            }
            "password" => reply.private_key_password.is_none() && reply.response.is_none(),
            "static" => reply.private_key_password.is_none(),
            "dynamic" | "text" => {
                reply.username.is_none()
                    && reply.password.is_none()
                    && reply.private_key_password.is_none()
            }
            "web" => {
                reply.username.is_none()
                    && reply.password.is_none()
                    && reply.private_key_password.is_none()
                    && reply.response.is_none()
            }
            _ => false,
        };
        if !matching_fields {
            return Err(invalid(
                "authentication fields do not match the current action",
            ));
        }
        let dynamic = action.kind == "dynamic";
        let user = reply
            .username
            .as_ref()
            .or(self.credentials.username.as_ref());
        let password = reply
            .password
            .as_ref()
            .or(self.credentials.password.as_ref());
        let result = match action.kind {
            "private_key" => vec![format!(
                "password \"Private Key\" {}",
                quote(
                    reply
                        .private_key_password
                        .as_deref()
                        .ok_or_else(|| invalid("private_key_password is required"))?
                )
            )],
            "password" | "static" => {
                let user = user.ok_or_else(|| invalid("username is required"))?;
                let password = password.ok_or_else(|| invalid("password is required"))?;
                let password = if action.kind == "static" {
                    format!(
                        "SCRV1:{}:{}",
                        STANDARD.encode(password),
                        STANDARD.encode(
                            reply
                                .response
                                .as_deref()
                                .ok_or_else(|| invalid("response is required"))?
                        )
                    )
                } else {
                    if reply.response.is_some() {
                        return Err(invalid(
                            "this authentication action does not accept a response",
                        ));
                    }
                    password.to_owned()
                };
                vec![
                    format!("username \"Auth\" {}", quote(user)),
                    format!("password \"Auth\" {}", quote(&password)),
                ]
            }
            "dynamic" => vec![
                format!(
                    "username \"Auth\" {}",
                    quote(user.ok_or_else(|| invalid("native challenge identity is missing"))?)
                ),
                format!(
                    "password \"Auth\" {}",
                    quote(&format!(
                        "CRV1::{}::{}",
                        action.opaque,
                        reply
                            .response
                            .as_deref()
                            .ok_or_else(|| invalid("response is required"))?
                    ))
                ),
            ],
            "text" => vec![format!(
                "cr-response {}",
                STANDARD.encode(
                    reply
                        .response
                        .as_deref()
                        .ok_or_else(|| invalid("response is required"))?
                )
            )],
            _ => {
                return Err(invalid(
                    "complete browser authentication at the provided URL",
                ));
            }
        };
        if let Some(v) = reply.username {
            self.credentials.username = Some(v);
        }
        if let Some(v) = reply.password {
            self.credentials.password = Some(v);
        }
        if let Some(v) = reply.private_key_password {
            self.credentials.private_key_password = Some(v);
        }
        if remember {
            if self.credentials.password.is_none()
                && self.credentials.private_key_password.is_none()
            {
                return Err(invalid("remember requires base credentials"));
            }
            self.remembered = true;
        }
        self.action = None;
        self.state = "authenticating".into();
        self.reason = "credentials_submitted".into();
        self.expires_at = None;
        self.automatic = true;
        if dynamic && !self.dynamic_ready {
            // Native retry can request credentials after the operator answers the challenge.
            self.dynamic_response = Some(result);
            Ok(Vec::new())
        } else {
            self.dynamic_ready = false;
            Ok(result)
        }
    }
}
