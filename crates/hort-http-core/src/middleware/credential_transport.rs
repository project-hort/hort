//! Observation of transport evidence at credential entry points, and the
//! one definition of whether a credential may travel on a given request.
//!
//! Two things live here because they answer two different questions about
//! the same request and must never be confused:
//!
//! * [`record_credential_transport`] reports the evidence actually derived
//!   (`tls` / `plaintext` / `unknown`). It is pure observation and says
//!   nothing about policy.
//! * [`credential_transport_verdict`] decides whether a credential may be
//!   carried. It consumes evidence **and** the operator's separately
//!   declared waiver, and a waiver never turns into evidence: a waived
//!   request still reports the evidence it had.
//!
//! The verdict is three-valued rather than a `bool` because `Waived` is
//! not `Allowed`. It is counted apart
//! ([`record_credential_transport_verdict`]), it is the one condition an
//! operator has to be able to see on a dashboard, and it is the state in
//! which this server does not claim the credential travelled under TLS.

use super::trust::{RequestTrust, TransportSecurity};

const METRIC: &str = "hort_credential_transport_total";
const ENTRY_POINT: &str = "entry_point";
const EVIDENCE: &str = "evidence";
const REFUSALS: &str = "hort_credential_transport_refusals_total";
const WAIVED: &str = "hort_credential_transport_waived_total";
const SCOPE: &str = "scope";

/// Reason string carried by a refusal: into the `426` response body, and
/// into the refusal `warn!`'s `reason` field.
///
/// The subject is any presented or issued credential. `Unknown` evidence
/// also does not establish whether the client spoke HTTP or HTTPS.
const REFUSAL_REASON: &str = "credential transport refused";

/// The `Upgrade` field value every transport refusal carries.
///
/// RFC 9110 §15.6.7 requires a `426` to name the protocol it wants, and
/// the value is the same on every credential surface — the refusal is
/// about the transport, not about the body shape the surface answers in.
/// It is `pub` because the OCI subtree answers in the Distribution-Spec
/// error envelope and would otherwise hand-type a second copy of a wire
/// literal in another crate.
pub const UPGRADE_OFFER: &str = "TLS/1.2, HTTP/1.1";

/// Whether a credential may travel on this request's transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialTransportVerdict {
    /// Positive evidence of TLS.
    Allowed,
    /// The operator has waived the requirement — for this peer scope or
    /// through the unscoped legacy flag. Carries which, so no caller
    /// reconstructs the metric label from a bare verdict.
    Waived(WaiverScope),
    /// No evidence and no waiver. Carries the reason for the body and the
    /// log line.
    Refused(&'static str),
}

/// Which operator instrument waived the transport requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaiverScope {
    /// `HORT_TLS_NOT_REQUIRED_FROM`: this request's raw TCP peer sits in a
    /// range the operator declared as not requiring TLS.
    Declared,
    /// `HORT_BEARER_ALLOW_OVER_HTTP`: accept a credential with no TLS
    /// evidence from anywhere.
    Unscoped,
}

impl WaiverScope {
    fn label(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Unscoped => "unscoped",
        }
    }
}

/// The single definition of "may a credential travel here".
///
/// Evidence is never fabricated; the waiver is the operator's declared
/// policy for this request's peer. They stay separate fields of
/// [`RequestTrust`]: a waiver changes what is accepted, never what the
/// server claims to have seen.
///
/// The precedence, which is the specification:
///
/// | Evidence | Peer | Unscoped flag | Verdict |
/// |---|---|---|---|
/// | — | no `RequestTrust` at all | any | `Refused` |
/// | `Tls` | any | any | `Allowed` |
/// | `Plaintext` | any | set | `Waived(Unscoped)` |
/// | `Plaintext` | any | unset | `Refused` — never waived by a scope |
/// | `Unknown` | a trusted proxy | unset | `Refused` — never waived by a scope |
/// | `Unknown` | not a trusted proxy, waived | — | `Waived(Declared)` |
/// | `Unknown` | anything else | set | `Waived(Unscoped)` |
/// | `Unknown` | anything else | unset | `Refused` |
///
/// Three rows carry the security argument:
///
/// * **`Plaintext` is never waived by a scope.** A trusted peer reporting
///   `proto=http` is positive evidence that an external client spoke
///   cleartext to the proxy; a declaration about an internal hop must not
///   be able to accept an external exposure.
/// * **A trusted-proxy peer is never waived by a scope.** An ingress
///   controller shares the pod range with the workloads behind it, so a
///   peer-keyed waiver would otherwise cover it and let an external
///   plaintext request mint a credential. The declaration means "this peer
///   is the client and its hop is plaintext by design", and a peer the
///   operator already declared to be a *proxy* is outside that meaning.
///   Listing one range in both variables therefore yields the stricter
///   behaviour.
/// * **A relayed request is never waived by a scope** — folded into
///   [`RequestTrust::tls_requirement_waived`] at derivation, because it is
///   a property of the request's headers rather than of this decision. An
///   untrusted ingress inside the waived range has `Unknown` evidence, and
///   without that condition the declared-scope row would accept an
///   external plaintext request through it.
///
/// `None` — no trust extension on the router — is `Refused`, never
/// `Allowed`. The caller passes the extension lookup straight in so that
/// absence cannot be forgotten at a call site.
///
/// The trusted-proxy exclusion is read here from `peer_trusted` even
/// though the derivation of `tls_requirement_waived` already applies it.
/// That is deliberate: the table above is this function's specification,
/// so the function satisfies it from its own inputs, and the row stays
/// pinnable by a unit test over the predicate alone. `RequestTrust` has
/// public fields and is constructed by every inbound test harness, so a
/// row that held only inside `evaluate_trust` would not be a property of
/// the decision.
pub fn credential_transport_verdict(
    trust: Option<&RequestTrust>,
    allow_over_http_unscoped: bool,
) -> CredentialTransportVerdict {
    let Some(trust) = trust else {
        return CredentialTransportVerdict::Refused(REFUSAL_REASON);
    };
    match trust.transport {
        TransportSecurity::Tls => CredentialTransportVerdict::Allowed,
        TransportSecurity::Unknown if !trust.peer_trusted && trust.tls_requirement_waived => {
            CredentialTransportVerdict::Waived(WaiverScope::Declared)
        }
        _ if allow_over_http_unscoped => CredentialTransportVerdict::Waived(WaiverScope::Unscoped),
        _ => CredentialTransportVerdict::Refused(REFUSAL_REASON),
    }
}

/// Count the policy outcome, separately from the observed evidence.
///
/// `Allowed` is not counted: it is the difference between
/// [`record_credential_transport`]'s total and these two, and a fourth
/// counter would carry no information the first three do not.
pub fn record_credential_transport_verdict(
    entry_point: CredentialEntryPoint,
    verdict: CredentialTransportVerdict,
) {
    match verdict {
        CredentialTransportVerdict::Allowed => {}
        CredentialTransportVerdict::Waived(scope) => {
            metrics::counter!(WAIVED, ENTRY_POINT => entry_point.label(), SCOPE => scope.label())
                .increment(1);
        }
        CredentialTransportVerdict::Refused(_) => {
            metrics::counter!(REFUSALS, ENTRY_POINT => entry_point.label()).increment(1);
        }
    }
}

/// Closed route classes on which a credential is presented or issued.
#[derive(Clone, Copy, Debug)]
pub enum CredentialEntryPoint {
    Require,
    Optional,
    Metrics,
    OciConsume,
    OciMint,
    Exchange,
}

impl CredentialEntryPoint {
    fn label(self) -> &'static str {
        match self {
            Self::Require => "require",
            Self::Optional => "optional",
            Self::Metrics => "metrics",
            Self::OciConsume => "oci_consume",
            Self::OciMint => "oci_mint",
            Self::Exchange => "exchange",
        }
    }
}

impl TransportSecurity {
    fn evidence_label(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Plaintext => "plaintext",
            Self::Unknown => "unknown",
        }
    }
}

/// Count a request at the point where it presents or would issue a credential.
/// A missing trust extension is recorded as `unknown`.
pub fn record_credential_transport(
    entry_point: CredentialEntryPoint,
    transport: Option<TransportSecurity>,
) {
    let evidence = transport
        .unwrap_or(TransportSecurity::Unknown)
        .evidence_label();
    metrics::counter!(METRIC, ENTRY_POINT => entry_point.label(), EVIDENCE => evidence)
        .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::MetricKind;

    fn trust(transport: TransportSecurity, peer_trusted: bool, waived: bool) -> RequestTrust {
        RequestTrust {
            client_ip: "192.0.2.1".parse().expect("test peer parses"),
            public_url: url::Url::parse("https://example.invalid").expect("test URL parses"),
            transport,
            peer_trusted,
            tls_requirement_waived: waived,
        }
    }

    /// Every row of the precedence table in
    /// [`credential_transport_verdict`]'s doc comment, named, in table
    /// order. A failure names the row rather than a line number.
    ///
    /// `waived` is carried through rows where the table says `—` for the
    /// peer column so that an accidental broadening — a scope reaching
    /// `Plaintext`, or reaching a trusted proxy — reports here rather
    /// than passing because the fixture happened not to declare one.
    #[test]
    fn the_precedence_table_is_the_verdict() {
        use CredentialTransportVerdict::{Allowed, Refused, Waived};
        use TransportSecurity::{Plaintext, Tls, Unknown};

        struct Row {
            name: &'static str,
            trust: Option<RequestTrust>,
            unscoped: bool,
            expected: CredentialTransportVerdict,
        }
        let rows = vec![
            Row {
                name: "no RequestTrust at all, flag unset",
                trust: None,
                unscoped: false,
                expected: Refused(REFUSAL_REASON),
            },
            Row {
                name: "no RequestTrust at all, flag set",
                trust: None,
                unscoped: true,
                expected: Refused(REFUSAL_REASON),
            },
            Row {
                name: "Tls, flag unset",
                trust: Some(trust(Tls, false, true)),
                unscoped: false,
                expected: Allowed,
            },
            Row {
                name: "Tls, flag set",
                trust: Some(trust(Tls, true, true)),
                unscoped: true,
                expected: Allowed,
            },
            Row {
                name: "Plaintext, flag set",
                trust: Some(trust(Plaintext, false, true)),
                unscoped: true,
                expected: Waived(WaiverScope::Unscoped),
            },
            Row {
                name: "Plaintext, flag unset — never waived by a scope",
                trust: Some(trust(Plaintext, false, true)),
                unscoped: false,
                expected: Refused(REFUSAL_REASON),
            },
            Row {
                name: "Plaintext from a trusted peer, flag unset — never waived by a scope",
                trust: Some(trust(Plaintext, true, true)),
                unscoped: false,
                expected: Refused(REFUSAL_REASON),
            },
            Row {
                name: "Unknown from a trusted proxy, flag unset — never waived by a scope",
                trust: Some(trust(Unknown, true, true)),
                unscoped: false,
                expected: Refused(REFUSAL_REASON),
            },
            Row {
                name: "Unknown, untrusted peer, waived",
                trust: Some(trust(Unknown, false, true)),
                unscoped: false,
                expected: Waived(WaiverScope::Declared),
            },
            Row {
                name: "Unknown, not waived, flag set",
                trust: Some(trust(Unknown, false, false)),
                unscoped: true,
                expected: Waived(WaiverScope::Unscoped),
            },
            Row {
                name: "Unknown, not waived, flag unset",
                trust: Some(trust(Unknown, false, false)),
                unscoped: false,
                expected: Refused(REFUSAL_REASON),
            },
        ];

        for row in &rows {
            assert_eq!(
                credential_transport_verdict(row.trust.as_ref(), row.unscoped),
                row.expected,
                "precedence row: {}",
                row.name
            );
        }
        // A waived request's evidence is always `unknown`: a scope reaches
        // no other evidence value, which is what keeps
        // `hort_credential_transport_total` answering "how much of my
        // traffic has no TLS evidence" after a waiver is in place.
        for row in &rows {
            if row.expected == Waived(WaiverScope::Declared) {
                assert_eq!(
                    row.trust
                        .as_ref()
                        .expect("declared waiver needs trust")
                        .transport,
                    Unknown,
                    "precedence row: {}",
                    row.name
                );
            }
        }
    }

    #[test]
    fn refusal_reason_names_the_whole_credential_surface() {
        assert_eq!(
            credential_transport_verdict(None, false),
            CredentialTransportVerdict::Refused("credential transport refused")
        );
    }

    #[test]
    fn verdict_outcomes_are_counted_apart_from_the_evidence() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            record_credential_transport_verdict(
                CredentialEntryPoint::Require,
                CredentialTransportVerdict::Allowed,
            );
            record_credential_transport_verdict(
                CredentialEntryPoint::Require,
                CredentialTransportVerdict::Refused(REFUSAL_REASON),
            );
            record_credential_transport_verdict(
                CredentialEntryPoint::Optional,
                CredentialTransportVerdict::Waived(WaiverScope::Declared),
            );
            record_credential_transport_verdict(
                CredentialEntryPoint::Exchange,
                CredentialTransportVerdict::Waived(WaiverScope::Unscoped),
            );
        });
        let snapshot = snapshotter.snapshot().into_vec();
        let mut found: Vec<String> = snapshot
            .iter()
            .map(|(key, _, _, _)| {
                let labels: Vec<String> = key
                    .key()
                    .labels()
                    .map(|label| format!("{}={}", label.key(), label.value()))
                    .collect();
                format!("{}{{{}}}", key.key().name(), labels.join(","))
            })
            .collect();
        found.sort();
        // `Allowed` emits nothing, so four records produce three series.
        assert_eq!(
            found,
            vec![
                format!("{REFUSALS}{{entry_point=require}}"),
                format!("{WAIVED}{{entry_point=exchange,scope=unscoped}}"),
                format!("{WAIVED}{{entry_point=optional,scope=declared}}"),
            ]
        );
        for (key, _, _, value) in snapshot {
            assert_eq!(key.kind(), MetricKind::Counter);
            assert!(matches!(value, DebugValue::Counter(1)));
        }
    }

    #[test]
    fn records_closed_entry_points_and_evidence_including_missing_trust() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            for entry in [
                CredentialEntryPoint::Require,
                CredentialEntryPoint::Optional,
                CredentialEntryPoint::Metrics,
                CredentialEntryPoint::OciConsume,
                CredentialEntryPoint::OciMint,
                CredentialEntryPoint::Exchange,
            ] {
                for transport in [
                    Some(TransportSecurity::Tls),
                    Some(TransportSecurity::Plaintext),
                    None,
                ] {
                    record_credential_transport(entry, transport);
                }
            }
        });
        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(snapshot.len(), 18);
        for (key, _, _, value) in snapshot {
            assert_eq!(key.kind(), MetricKind::Counter);
            assert_eq!(key.key().name(), METRIC);
            assert!(matches!(value, DebugValue::Counter(1)));
            let labels: Vec<_> = key.key().labels().collect();
            assert_eq!(labels.len(), 2);
            assert!(labels.iter().any(|label| label.key() == ENTRY_POINT));
            assert!(labels.iter().any(|label| label.key() == EVIDENCE));
        }
    }
}
