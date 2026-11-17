use picky_asn1::restricted_string::IA5String;
#[cfg(feature = "scard")]
use picky_krb::constants::error_codes::KDC_ERR_ETYPE_NOSUPP;
use picky_krb::constants::error_codes::{KDC_ERR_WRONG_REALM, KRB_AP_ERR_SKEW};
use picky_krb::data_types::{KerberosStringAsn1, KrbResult, Realm};
use picky_krb::messages::{AsRep, AsReq, KdcReqBody, KrbError};
use time::{Duration, OffsetDateTime};

use crate::kerberos::EncryptionParams;
use crate::kerberos::client::extractors::extract_preauth_salt;
use crate::kerberos::client::generators::{GenerateAsPaDataOptions, GenerateKeytabPaDataOptions, generate_as_req};
use crate::kerberos::client::kdc::decode_kdc_reply;
use crate::kerberos::pa_datas::AsReqPaDataOptions;
#[cfg(feature = "scard")]
use crate::pk_init::KeyAgreement;
use crate::{CredentialsBuffers, Error, ErrorKind, Kerberos, Result, Secret};

/// Maximum number of client referrals to follow in the AS exchange.
const MAX_REFERRAL_HOPS: usize = 5;

#[derive(Debug)]
pub(crate) enum AsExchangeOutput {
    SendRequest(AsReq),
    Done(AsRep, String),
}

#[derive(Debug, Clone, PartialEq)]
enum AsExchangeState {
    Initial,
    PreauthRequiredErrorResponse,
    AsRequest,
    AsRepResponse,
}

/// Performs the AS exchange as specified in [RFC 4120, section 3.1](https://www.rfc-editor.org/rfc/rfc4120#section-3.1).
///
/// On a KDC clock-skew error, retries pre-authentication once using the server
/// time in the error. The offset is kept on the client context for subsequent
/// TGS and AP authenticators; other errors are returned without retrying.
#[derive(Debug, Clone, PartialEq)]
pub struct AsExchange {
    state: AsExchangeState,
    kdc_req_body: KdcReqBody,
    retried_skew: bool,
    hops: usize,
    // Instead of storing the `AsReqPaDataOptions` directly, we store its individual components (fields below).
    // This design avoids introducing lifetime requirement that would require huge refactoring.
    // The `AsReqPaDataOptions` is cheaply reconstructed at each step using the `build_pa_data_options` method.
    password: Secret<String>,
    salt: Vec<u8>,
    #[cfg(feature = "scard")]
    key_agreement: KeyAgreement,
    #[cfg(feature = "scard")]
    authenticator_nonce: u32,
}

impl AsExchange {
    pub(crate) fn new(
        kdc_req_body: KdcReqBody,
        password: Secret<String>,
        salt: Vec<u8>,
        #[cfg(feature = "scard")] key_agreement: KeyAgreement,
        #[cfg(feature = "scard")] authenticator_nonce: u32,
    ) -> Self {
        Self {
            state: AsExchangeState::Initial,
            kdc_req_body,
            retried_skew: false,
            hops: 0,
            password,
            salt,
            #[cfg(feature = "scard")]
            key_agreement,
            #[cfg(feature = "scard")]
            authenticator_nonce,
        }
    }

    pub(crate) fn step(
        &mut self,
        client: &mut Kerberos,
        credentials: &CredentialsBuffers,
        response: &[u8],
    ) -> Result<AsExchangeOutput> {
        loop {
            match self.state {
                AsExchangeState::Initial => {
                    let mut pa_data_options = self.build_pa_data_options(credentials, &client.encryption_params)?;

                    pa_data_options.with_pre_auth(false);
                    let pa_datas = pa_data_options.generate(client.current_kdc_time()?)?;
                    let as_req = generate_as_req(pa_datas, self.kdc_req_body.clone());

                    self.state = AsExchangeState::PreauthRequiredErrorResponse;
                    return Ok(AsExchangeOutput::SendRequest(as_req));
                }
                AsExchangeState::PreauthRequiredErrorResponse => {
                    let as_rep: KrbResult<AsRep> = decode_kdc_reply(
                        response,
                        client.is_iakerb(),
                        &mut client.iakerb_cookie,
                        &mut client.iakerb_gss_transcript,
                    )?;

                    if as_rep.is_ok() {
                        error!(
                            "KDC replied with AS_REP to the AS_REQ without the encrypted timestamp. The KRB_ERROR expected."
                        );

                        return Err(Error::new(
                            ErrorKind::InvalidToken,
                            "KDC server should not process AS_REQ without the pa-pac data",
                        ));
                    }

                    let krb_error = as_rep.unwrap_err();

                    warn!(?krb_error, "KDC replied with KRB_ERROR to the AS_REQ");

                    if krb_error.0.error_code.0 == KDC_ERR_WRONG_REALM {
                        self.follow_client_referral(client, &krb_error)?;
                        self.state = AsExchangeState::Initial;

                        continue;
                    }

                    if is_smart_card_preauth_hint(credentials, &krb_error) {
                        debug!(
                            "KDC replied with KDC_ERR_ETYPE_NOSUPP to the smart card AS_REQ; continuing with PKINIT"
                        );
                    } else if let Some(salt) =
                        extract_preauth_salt(
                            &krb_error,
                            self.kdc_req_body.realm.0.0.as_utf8(),
                            self.kdc_req_body.cname.0.as_ref().ok_or_else(|| {
                                Error::new(ErrorKind::InvalidParameter, "missing client name in AS-REQ")
                            })?,
                        )?
                    {
                        debug!("salt extracted successfully from the KRB_ERROR");
                        self.salt = salt.into_bytes();
                    }

                    self.state = AsExchangeState::AsRequest;

                    continue;
                }
                AsExchangeState::AsRequest => {
                    let mut pa_data_options = self.build_pa_data_options(credentials, &client.encryption_params)?;

                    pa_data_options.with_pre_auth(true);
                    let pa_datas = pa_data_options.generate(client.current_kdc_time()?)?;

                    self.state = AsExchangeState::AsRepResponse;
                    return Ok(AsExchangeOutput::SendRequest(generate_as_req(
                        pa_datas,
                        self.kdc_req_body.clone(),
                    )));
                }
                AsExchangeState::AsRepResponse => {
                    let received_at = OffsetDateTime::now_utc();

                    let as_rep: KrbResult<AsRep> = decode_kdc_reply(
                        response,
                        client.is_iakerb(),
                        &mut client.iakerb_cookie,
                        &mut client.iakerb_gss_transcript,
                    )?;

                    match as_rep {
                        Ok(as_rep) => {
                            return Ok(AsExchangeOutput::Done(
                                as_rep,
                                String::from_utf8_lossy(&self.salt).into_owned(),
                            ));
                        }
                        Err(err) if !self.retried_skew && err.0.error_code.0 == KRB_AP_ERR_SKEW => {
                            client.clock_offset = clock_offset_from_error(&err, received_at)?;
                            self.retried_skew = true;
                            debug!(offset = ?client.clock_offset, "Retrying AS exchange with KDC clock offset");

                            self.state = AsExchangeState::AsRequest;
                            continue;
                        }
                        Err(err) if err.0.error_code.0 == KDC_ERR_WRONG_REALM => {
                            self.follow_client_referral(client, &err)?;
                            self.state = AsExchangeState::Initial;
                            continue;
                        }
                        Err(err) => {
                            error!(?err, "AS exchange error");
                            return Err(err.into());
                        }
                    }
                }
            }
        }
    }

    /// Retargets the AS-REQ at the realm named by a `KDC_ERR_WRONG_REALM` error
    /// ([RFC 6806, section 7](https://www.rfc-editor.org/rfc/rfc6806#section-7)).
    fn follow_client_referral(&mut self, client: &mut Kerberos, error: &KrbError) -> Result<()> {
        let current_realm = self.kdc_req_body.realm.0.0.as_utf8().to_owned();

        let next_realm = error
            .0
            .crealm
            .0
            .as_ref()
            .map(|crealm| crealm.0.0.as_utf8().to_owned())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!("KDC_ERR_WRONG_REALM from realm `{current_realm}` does not name a referral realm"),
                )
            })?;

        self.hops += 1;
        if self.hops > MAX_REFERRAL_HOPS {
            return Err(Error::new(
                ErrorKind::NoAuthenticatingAuthority,
                format!("exceeded maximum Kerberos client referral hops ({MAX_REFERRAL_HOPS}) in the AS exchange"),
            ));
        }
        if next_realm.eq_ignore_ascii_case(&current_realm) {
            return Err(Error::new(
                ErrorKind::NoAuthenticatingAuthority,
                format!("Kerberos client referral did not progress past realm `{current_realm}`"),
            ));
        }

        debug!(%current_realm, %next_realm, "Received client referral; retargeting AS-REQ at referral realm");

        let krbtgt_realm = KerberosStringAsn1::from(IA5String::from_string(next_realm.clone())?);
        if let Some(sname) = self.kdc_req_body.sname.0.as_mut()
            && let Some(realm_component) = sname.0.name_string.0.0.get_mut(1)
        {
            *realm_component = krbtgt_realm;
        }
        self.kdc_req_body.realm.0 = Realm::from(IA5String::from_string(next_realm.clone())?);
        client.realm = Some(next_realm);

        Ok(())
    }

    fn build_pa_data_options<'a>(
        &'a mut self,
        credentials: &'a CredentialsBuffers,
        enc_params: &EncryptionParams,
    ) -> Result<AsReqPaDataOptions<'a>> {
        Ok(match credentials {
            CredentialsBuffers::AuthIdentity(_) => AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
                password: &self.password,
                salt: self.salt.clone(),
                enc_params: enc_params.clone(),
                with_pre_auth: false,
            }),
            CredentialsBuffers::Keytab(keytab) => AsReqPaDataOptions::Keytab(GenerateKeytabPaDataOptions {
                key: keytab.key.clone(),
                key_enctype: keytab.key_enctype.clone(),
                with_pre_auth: false,
            }),
            #[cfg(feature = "scard")]
            CredentialsBuffers::SmartCard(scard_identity_buffer) => {
                use crate::smartcard::SmartCard;
                use crate::{SmartCardIdentity, pk_init};

                let scard_identity = SmartCardIdentity::try_from(scard_identity_buffer)?;

                let mut smart_card = SmartCard::from_credentials(&scard_identity)?;
                let p2p_cert = scard_identity.certificate;

                AsReqPaDataOptions::SmartCard(Box::new(pk_init::GenerateAsPaDataOptions {
                    p2p_cert,
                    kdc_req_body: &self.kdc_req_body,
                    key_agreement: self.key_agreement.clone(),
                    sign_data: Box::new(move |data_to_sign| smart_card.sign(data_to_sign)),
                    with_pre_auth: false,
                    authenticator_nonce: self.authenticator_nonce,
                }))
            }
        })
    }
}

/// Returns `true` when the KDC reply to the AS-REQ without pre-authentication data should
/// be treated as `preauth required`.
///
/// The Windows Server 2016 KDC answers a smart card AS-REQ without pre-authentication data
/// with `KDC_ERR_ETYPE_NOSUPP` instead of `KDC_ERR_PREAUTH_REQUIRED`. The error is misleading,
/// since the subsequent AS-REQ offers the same encryption types along with pre-authentication
/// data and succeeds.
///
/// Note: this is workaround for the Windows Server 2016 KDC behavior, which is not compliant with RFC 4120.
#[cfg(feature = "scard")]
fn is_smart_card_preauth_hint(credentials: &CredentialsBuffers, error: &KrbError) -> bool {
    matches!(credentials, CredentialsBuffers::SmartCard(_)) && error.0.error_code.0 == KDC_ERR_ETYPE_NOSUPP
}

#[cfg(not(feature = "scard"))]
fn is_smart_card_preauth_hint(_credentials: &CredentialsBuffers, _error: &KrbError) -> bool {
    false
}

pub(crate) fn clock_offset_from_error(error: &KrbError, received_at: OffsetDateTime) -> Result<Duration> {
    let seconds = OffsetDateTime::try_from(error.0.stime.0.0.clone())
        .map_err(|_| Error::new(ErrorKind::InvalidToken, "KDC skew error has invalid server time"))?;
    let usec = error.0.susec.0.0.as_slice();
    if usec.len() > 4 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "KDC skew error has invalid microseconds",
        ));
    }
    let microseconds = usec.iter().fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    if microseconds > 999_999 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "KDC skew error has invalid microseconds",
        ));
    }
    let server_time = seconds
        .checked_add(Duration::microseconds(i64::from(microseconds)))
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "KDC skew error has invalid server time"))?;
    Ok(server_time - received_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientRequestFlags;
    use crate::kerberos::client::generators::{GenerateAsReqOptions, generate_as_req_kdc_body};
    use crate::kerberos::config::KerberosConfig;
    use picky_asn1::wrapper::{
        Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag4, ExplicitContextTag5,
        ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag9, ExplicitContextTag10, IntegerAsn1, Optional,
    };
    use picky_krb::data_types::{KerberosTime, Microseconds, PrincipalName};
    use picky_krb::messages::KrbErrorInner;
    use rand_core::SeedableRng;

    fn realm(name: &str) -> Realm {
        Realm::from(IA5String::from_string(name.to_owned()).unwrap())
    }

    fn wrong_realm_error(crealm: Option<&str>) -> KrbError {
        KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![30])),
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: ExplicitContextTag4::from(KerberosTime::from(picky_asn1::date::GeneralizedTime::from(
                OffsetDateTime::UNIX_EPOCH,
            ))),
            susec: ExplicitContextTag5::from(Microseconds::from(vec![0])),
            error_code: ExplicitContextTag6::from(KDC_ERR_WRONG_REALM),
            crealm: Optional::from(crealm.map(|name| ExplicitContextTag7::from(realm(name)))),
            cname: Optional::from(None),
            realm: ExplicitContextTag9::from(realm("EXAMPLE.COM")),
            sname: ExplicitContextTag10::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string("krbtgt".to_owned()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap()),
                ])),
            }),
            e_text: Optional::from(None),
            e_data: Optional::from(None),
        })
    }

    fn exchange_for(realm_name: &str) -> (AsExchange, Kerberos) {
        let body = generate_as_req_kdc_body(&GenerateAsReqOptions {
            realm: realm_name,
            username: "alice",
            cname_type: 1,
            snames: &["krbtgt", realm_name],
            nonce: 1,
            hostname: "host",
            context_requirements: ClientRequestFlags::empty(),
        })
        .unwrap();
        let client = Kerberos::new_client_from_config(KerberosConfig::new_with_kdc_url(
            "tcp://kdc.example.com:88",
            "host".into(),
        ))
        .unwrap();
        let exchange = AsExchange::new(
            body,
            Secret::new(String::new()),
            Vec::new(),
            #[cfg(feature = "scard")]
            KeyAgreement::Dh(crate::pku2u::generate_client_dh_parameters(
                &mut rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng).unwrap(),
            )),
            #[cfg(feature = "scard")]
            0,
        );
        (exchange, client)
    }

    #[test]
    fn wrong_realm_retargets_request_at_referral_realm_keeping_client_name() {
        let (mut exchange, mut client) = exchange_for("EXAMPLE.COM");

        exchange
            .follow_client_referral(&mut client, &wrong_realm_error(Some("CORP.EXAMPLE.COM")))
            .unwrap();

        let body = &exchange.kdc_req_body;
        assert_eq!(body.realm.0.0.as_utf8(), "CORP.EXAMPLE.COM");
        let sname = &body.sname.0.as_ref().unwrap().0.name_string.0.0;
        assert_eq!(sname[0].0.as_utf8(), "krbtgt");
        assert_eq!(sname[1].0.as_utf8(), "CORP.EXAMPLE.COM");
        assert_eq!(body.cname.0.as_ref().unwrap().0.name_string.0.0[0].0.as_utf8(), "alice");
        assert_eq!(client.realm.as_deref(), Some("CORP.EXAMPLE.COM"));
    }

    #[test]
    fn wrong_realm_without_referral_realm_fails() {
        let (mut exchange, mut client) = exchange_for("EXAMPLE.COM");

        assert!(
            exchange
                .follow_client_referral(&mut client, &wrong_realm_error(None))
                .is_err()
        );
    }

    #[test]
    fn wrong_realm_pointing_at_same_realm_fails() {
        let (mut exchange, mut client) = exchange_for("EXAMPLE.COM");

        assert!(
            exchange
                .follow_client_referral(&mut client, &wrong_realm_error(Some("example.com")))
                .is_err()
        );
    }

    #[test]
    fn referrals_are_limited() {
        let (mut exchange, mut client) = exchange_for("R0.EXAMPLE.COM");

        for hop in 1..=MAX_REFERRAL_HOPS {
            exchange
                .follow_client_referral(&mut client, &wrong_realm_error(Some(&format!("R{hop}.EXAMPLE.COM"))))
                .unwrap();
        }

        assert!(
            exchange
                .follow_client_referral(&mut client, &wrong_realm_error(Some("LAST.EXAMPLE.COM")))
                .is_err()
        );
    }
}
