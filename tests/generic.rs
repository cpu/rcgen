mod util;

#[cfg(feature = "pem")]
mod test_key_params_mismatch {
	use crate::util;

	use rcgen::{Certificate, KeyPair, RcgenError};
	use std::collections::hash_map::DefaultHasher;
	use std::hash::{Hash, Hasher};

	fn generate_hash<T: Hash>(subject: &T) -> u64 {
		let mut hasher = DefaultHasher::new();
		subject.hash(&mut hasher);
		hasher.finish()
	}

	#[test]
	fn test_key_params_mismatch() {
		let available_key_params = [
			&rcgen::PKCS_RSA_SHA256,
			&rcgen::PKCS_ECDSA_P256_SHA256,
			&rcgen::PKCS_ECDSA_P384_SHA384,
			&rcgen::PKCS_ED25519,
		];
		for (i, kalg_1) in available_key_params.iter().enumerate() {
			for (j, kalg_2) in available_key_params.iter().enumerate() {
				if i == j {
					assert_eq!(*kalg_1, *kalg_2);
					assert_eq!(generate_hash(*kalg_1), generate_hash(*kalg_2));
					continue;
				}

				assert_ne!(*kalg_1, *kalg_2);
				assert_ne!(generate_hash(*kalg_1), generate_hash(*kalg_2));

				let mut wrong_params = util::default_params();
				if i != 0 {
					wrong_params.key_pair = Some(KeyPair::generate(kalg_1).unwrap());
				} else {
					let kp = KeyPair::from_pem(util::RSA_TEST_KEY_PAIR_PEM).unwrap();
					wrong_params.key_pair = Some(kp);
				}
				wrong_params.alg = *kalg_2;

				assert_eq!(
					Certificate::from_params(wrong_params).err(),
					Some(RcgenError::CertificateKeyPairMismatch),
					"i: {} j: {}",
					i,
					j
				);
			}
		}
	}
}

#[cfg(feature = "x509-parser")]
mod test_convert_x509_subject_alternative_name {
	use rcgen::{
		BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, SanType,
		PKCS_ECDSA_P256_SHA256,
	};
	use std::net::{IpAddr, Ipv4Addr};

	#[test]
	fn converts_from_ip() {
		let ip = Ipv4Addr::new(2, 4, 6, 8);
		let ip_san = SanType::IpAddress(IpAddr::V4(ip));

		let mut params = super::util::default_params();

		// Add the SAN we want to test the parsing for
		params.subject_alt_names.push(ip_san.clone());

		// Because we're using a function for CA certificates
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

		let cert = Certificate::from_params(params).unwrap();

		// Serialize our cert that has our chosen san, so we can testing parsing/deserializing it.
		let ca_der = cert.serialize_der().unwrap();

		// Arbitrary key pair not used with the test, but required by the parsing function
		let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).unwrap();

		let actual = CertificateParams::from_ca_cert_der(&ca_der, key_pair).unwrap();

		assert!(actual.subject_alt_names.contains(&ip_san));
	}
}

#[cfg(feature = "x509-parser")]
mod test_csr_exts {
	use crate::util;
	use rcgen::{
		BasicConstraints, Certificate, CrlDistributionPoint, GeneralSubtree, KeyUsagePurpose,
		SanType,
	};
	use x509_parser::prelude::{
		FromDer, ParsedExtension, X509Certificate, X509CertificationRequest,
	};

	#[test]
	fn test_rcgen_extensions() {
		// Create a certificate that has several rcgen managed extensions (e.g. not custom extensions).
		let mut params = util::default_params();
		let san_name = "san.example.com";
		params.subject_alt_names = vec![SanType::DnsName(san_name.into())];
		let path_len_constraint = 3;
		params.is_ca = rcgen::IsCa::Ca(BasicConstraints::Constrained(path_len_constraint));
		params.key_usages = vec![
			KeyUsagePurpose::DigitalSignature,
			KeyUsagePurpose::KeyEncipherment,
		];
		params.extended_key_usages = vec![
			rcgen::ExtendedKeyUsagePurpose::ServerAuth,
			rcgen::ExtendedKeyUsagePurpose::ClientAuth,
		];
		let permitted_subtree_dns = "example.com";
		let excluded_subtree_dns = "example.org";
		params.name_constraints = Some(rcgen::NameConstraints {
			permitted_subtrees: vec![GeneralSubtree::DnsName(permitted_subtree_dns.into())],
			excluded_subtrees: vec![GeneralSubtree::DnsName(excluded_subtree_dns.into())],
		});
		let distribution_point_uri = "http://example.com";
		params.crl_distribution_points = vec![CrlDistributionPoint {
			uris: vec![distribution_point_uri.into()],
		}];
		let cert = Certificate::from_params(params).unwrap();
		let cert_der = cert.serialize_der().unwrap();
		let csr_der = cert.serialize_request_der().unwrap();

		// Parse the self-signed test certificate, and a CSR generated from the test certificate with x509-parser.
		let (_, x509_cert) = X509Certificate::from_der(&cert_der).unwrap();
		let (_, x509_csr) = X509CertificationRequest::from_der(&csr_der).unwrap();

		// Helper macro that tests both the parsed cert and CSR have an extension with specific
		// properties.
		macro_rules! assert_paired_ext {
			($oid:ident, $critical:expr, $pattern:pat, $parsed_expr:expr) => {{
				// 1. Find the extension in the certificate.
				let cert_ext = x509_cert
					.get_extension_unique(&x509_parser::oid_registry::$oid)
					.expect(concat!("malformed cert ext for ", stringify!($oid)))
					.expect(concat!("missing cert ext for ", stringify!($oid)));

				// 2. Verify criticality.
				assert_eq!(
					cert_ext.critical, $critical,
					concat!("wrong criticality for ", stringify!($oid))
				);

				// 3. Verify the parsed representation of the extension.
				match cert_ext.parsed_extension() {
					$pattern => $parsed_expr,
					_ => panic!(concat!(
						"unexpected parsed extension for ",
						stringify!($oid)
					)),
				};

				// 4. Verify the parsed CSR has the extension, and that it has the correct
				//    parsed representation.
				x509_csr
					.requested_extensions()
					.expect("missing CSR requested extensions")
					.find_map(|ext| match ext {
						$pattern => Some($parsed_expr),
						_ => None,
					})
					.expect(concat!("missing CSR extension for ", stringify!($oid)))
			}};
		}

		assert_paired_ext!(
			OID_X509_EXT_SUBJECT_ALT_NAME,
			false,
			ParsedExtension::SubjectAlternativeName(san),
			{
				san.general_names
					.iter()
					.find(|name| match name {
						x509_parser::prelude::GeneralName::DNSName(name) => name == &san_name,
						_ => false,
					})
					.expect("missing expected SAN");
			}
		);

		assert_paired_ext!(
			OID_X509_EXT_BASIC_CONSTRAINTS,
			true,
			ParsedExtension::BasicConstraints(bc),
			{
				assert!(bc.ca);
				assert_eq!(
					bc.path_len_constraint.expect("missing path len constraint"),
					path_len_constraint as u32
				);
			}
		);

		fn assert_subtree_dns(
			subtrees: Vec<x509_parser::prelude::GeneralSubtree>,
			expected_dns: &str,
		) {
			subtrees
				.iter()
				.find(
					|subtree|
						matches!(subtree.base, x509_parser::prelude::GeneralName::DNSName(dns) if dns == expected_dns)
				)
				.expect("missing expected subtree URI");
		}
		assert_paired_ext!(
			OID_X509_EXT_NAME_CONSTRAINTS,
			true,
			ParsedExtension::NameConstraints(name_constraints),
			{
				assert_subtree_dns(
					name_constraints
						.permitted_subtrees
						.clone()
						.expect("missing permitted subtrees"),
					&permitted_subtree_dns,
				);
				assert_subtree_dns(
					name_constraints
						.excluded_subtrees
						.clone()
						.expect("missing excluded subtrees"),
					&excluded_subtree_dns,
				);
			}
		);

		fn assert_crl_dps_uri(
			crl_dps: &x509_parser::prelude::CRLDistributionPoints,
			expected: &str,
		) {
			crl_dps
				.iter()
				.find(|dp| {
					let full_names = match dp
						.distribution_point
						.clone()
						.expect("missing distribution point name")
					{
						x509_parser::prelude::DistributionPointName::FullName(full_names) => {
							full_names
						},
						_ => panic!("missing full names"),
					};

					full_names.iter().find(|general_name|
						matches!(general_name, x509_parser::prelude::GeneralName::URI(uri) if uri == &expected)).is_some()
				})
				.expect("missing expected CRL distribution point URI");
		}
		assert_paired_ext!(
			OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
			false,
			ParsedExtension::CRLDistributionPoints(crl_dps),
			assert_crl_dps_uri(crl_dps, &distribution_point_uri)
		);

		assert_paired_ext!(
			OID_X509_EXT_KEY_USAGE,
			true,
			ParsedExtension::KeyUsage(ku),
			{
				assert!(ku.digital_signature());
				assert!(ku.key_encipherment());
				assert!(!ku.non_repudiation());
				assert!(!ku.key_agreement());
				assert!(!ku.key_cert_sign());
				assert!(!ku.encipher_only());
				assert!(!ku.decipher_only());
			}
		);

		assert_paired_ext!(
			OID_X509_EXT_EXTENDED_KEY_USAGE,
			false,
			ParsedExtension::ExtendedKeyUsage(eku),
			{
				assert!(eku.server_auth);
				assert!(eku.client_auth);
				assert!(!eku.any);
				assert!(eku.other.is_empty());
				assert!(!eku.code_signing);
				assert!(!eku.ocsp_signing);
				assert!(!eku.email_protection);
				assert!(!eku.time_stamping);
			}
		);

		assert_paired_ext!(
			OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
			false,
			ParsedExtension::SubjectKeyIdentifier(ski),
			assert_eq!(ski.0, &cert.get_key_identifier())
		);

		// We should find the AKI extension in the self-signed certificate.
		let aki = x509_cert
			.get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
			.expect("malformed OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER")
			.expect("missing OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER");
		assert!(!aki.critical);
		match aki.parsed_extension() {
			ParsedExtension::AuthorityKeyIdentifier(aki) => assert_eq!(
				aki.clone()
					.key_identifier
					.expect("missing key identifier")
					.0,
				&cert.get_key_identifier()
			),
			_ => panic!("unexpected parsed extension type"),
		};

		// We should not find the AKI extension in the CSR. That's provided by an issuer
		// when issuing the certificate.
		assert_eq!(
			x509_csr
				.requested_extensions()
				.unwrap()
				.find(|ext| { matches!(ext, ParsedExtension::AuthorityKeyIdentifier(_)) }),
			None
		);
	}
}

#[cfg(feature = "x509-parser")]
mod test_x509_custom_ext {
	use crate::util;

	use rcgen::{Certificate, CustomExtension};
	use x509_parser::oid_registry::asn1_rs;
	use x509_parser::prelude::{
		FromDer, ParsedCriAttribute, X509Certificate, X509CertificationRequest,
	};

	#[test]
	fn custom_ext() {
		// Create an imaginary critical custom extension for testing.
		let test_oid = asn1_rs::Oid::from(&[2, 5, 29, 999999]).unwrap();
		let test_ext = yasna::construct_der(|writer| {
			writer.write_utf8_string("🦀 greetz to ferris 🦀");
		});
		let mut custom_ext = CustomExtension::from_oid_content(
			test_oid.iter().unwrap().collect::<Vec<u64>>().as_slice(),
			test_ext.clone(),
		);
		custom_ext.set_criticality(true);

		// Generate a certificate with the custom extension, parse it with x509-parser.
		let mut params = util::default_params();
		params.custom_extensions = vec![custom_ext];
		// Ensure the custom exts. being omitted into a CSR doesn't require SAN ext being present.
		// See https://github.com/rustls/rcgen/issues/122
		params.subject_alt_names = Vec::default();
		let test_cert = Certificate::from_params(params).unwrap();
		let test_cert_der = test_cert.serialize_der().unwrap();
		let (_, x509_test_cert) = X509Certificate::from_der(&test_cert_der).unwrap();

		// We should be able to find the extension by OID, with expected criticality and value.
		let favorite_drink_ext = x509_test_cert
			.get_extension_unique(&test_oid)
			.expect("invalid extensions")
			.expect("missing custom extension");
		assert_eq!(favorite_drink_ext.critical, true);
		assert_eq!(favorite_drink_ext.value, test_ext);

		// Generate a CSR with the custom extension, parse it with x509-parser.
		let test_cert_csr_der = test_cert.serialize_request_der().unwrap();
		let (_, x509_csr) = X509CertificationRequest::from_der(&test_cert_csr_der).unwrap();

		// We should find that the CSR contains requested extensions.
		// Note: we can't use `x509_csr.requested_extensions()` here because it maps the raw extension
		// request extensions to their parsed form, and of course x509-parser doesn't parse our custom extension.
		let exts = x509_csr
			.certification_request_info
			.iter_attributes()
			.find_map(|attr| {
				if let ParsedCriAttribute::ExtensionRequest(requested) = &attr.parsed_attribute() {
					Some(requested.extensions.iter().collect::<Vec<_>>())
				} else {
					None
				}
			})
			.expect("missing requested extensions");

		// We should find the custom extension with expected criticality and value.
		let custom_ext = exts
			.iter()
			.find(|ext| ext.oid == test_oid)
			.expect("missing requested custom extension");
		assert_eq!(custom_ext.critical, true);
		assert_eq!(custom_ext.value, test_ext);
	}
}

#[cfg(feature = "x509-parser")]
mod test_x509_parser_crl {
	use crate::util;
	use x509_parser::num_bigint::BigUint;
	use x509_parser::prelude::{FromDer, X509Certificate};
	use x509_parser::revocation_list::CertificateRevocationList;
	use x509_parser::x509::X509Version;

	#[test]
	fn parse_crl() {
		// Create a CRL with one revoked cert, and an issuer to sign the CRL.
		let (crl, issuer) = util::test_crl();
		let revoked_cert = crl.get_params().revoked_certs.first().unwrap();
		let revoked_cert_serial = BigUint::from_bytes_be(revoked_cert.serial_number.as_ref());
		let issuer_der = issuer.serialize_der().unwrap();
		let (_, x509_issuer) = X509Certificate::from_der(&issuer_der).unwrap();

		// Serialize the CRL signed by the issuer in DER form.
		let crl_der = crl.serialize_der_with_signer(&issuer).unwrap();

		// We should be able to parse the CRL with x509-parser without error.
		let (_, x509_crl) =
			CertificateRevocationList::from_der(&crl_der).expect("failed to parse CRL DER");

		// The properties of the CRL should match expected.
		assert_eq!(x509_crl.version().unwrap(), X509Version(1));
		assert_eq!(x509_crl.issuer(), x509_issuer.subject());
		assert_eq!(
			x509_crl.last_update().to_datetime().unix_timestamp(),
			crl.get_params().this_update.unix_timestamp()
		);
		assert_eq!(
			x509_crl
				.next_update()
				.unwrap()
				.to_datetime()
				.unix_timestamp(),
			crl.get_params().next_update.unix_timestamp()
		);
		// TODO: Waiting on x509-parser 0.15.1 to be released.
		// let crl_number = BigUint::from_bytes_be(crl.get_params().crl_number.as_ref());
		// assert_eq!(x509_crl.crl_number().unwrap(), &crl_number);

		// We should find the expected revoked certificate serial with the correct reason code.
		let x509_revoked_cert = x509_crl
			.iter_revoked_certificates()
			.next()
			.expect("failed to find revoked cert in CRL");
		assert_eq!(x509_revoked_cert.user_certificate, revoked_cert_serial);
		let (_, reason_code) = x509_revoked_cert.reason_code().unwrap();
		assert_eq!(reason_code.0, revoked_cert.reason_code.unwrap() as u8);

		// The issuing distribution point extension should be present and marked critical.
		let issuing_dp_ext = x509_crl
			.extensions()
			.iter()
			.find(|ext| {
				ext.oid == x509_parser::oid_registry::OID_X509_EXT_ISSUER_DISTRIBUTION_POINT
			})
			.expect("failed to find issuing distribution point extension");
		assert!(issuing_dp_ext.critical);
		// TODO: x509-parser does not yet parse the CRL issuing DP extension for further examination.

		// We should be able to verify the CRL signature with the issuer.
		assert!(x509_crl.verify_signature(&x509_issuer.public_key()).is_ok());
	}
}

#[cfg(feature = "x509-parser")]
mod test_parse_crl_dps {
	use crate::util;
	use x509_parser::extensions::{DistributionPointName, ParsedExtension};

	#[test]
	fn parse_crl_dps() {
		// Generate and parse a certificate that includes two CRL distribution points.
		let der = util::cert_with_crl_dps();
		let (_, parsed_cert) = x509_parser::parse_x509_certificate(&der).unwrap();

		// We should find a CRL DP extension was parsed.
		let crl_dps = parsed_cert
			.get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
			.expect("malformed CRL distribution points extension")
			.expect("missing CRL distribution points extension");

		// The extension should not be critical.
		assert!(!crl_dps.critical);

		// We should be able to parse the definition.
		let crl_dps = match crl_dps.parsed_extension() {
			ParsedExtension::CRLDistributionPoints(crl_dps) => crl_dps,
			_ => panic!("unexpected parsed extension type"),
		};

		// There should be two DPs.
		assert_eq!(crl_dps.points.len(), 2);

		// Each distribution point should only include a distribution point name holding a sequence
		// of general names.
		let general_names = crl_dps
			.points
			.iter()
			.flat_map(|dp| {
				// We shouldn't find a cRLIssuer or onlySomeReasons field.
				assert!(dp.crl_issuer.is_none());
				assert!(dp.reasons.is_none());

				match dp
					.distribution_point
					.as_ref()
					.expect("missing distribution point name")
				{
					DistributionPointName::FullName(general_names) => general_names.iter(),
					DistributionPointName::NameRelativeToCRLIssuer(_) => {
						panic!("unexpected name relative to cRL issuer")
					},
				}
			})
			.collect::<Vec<_>>();

		// All of the general names should be URIs.
		let uris = general_names
			.iter()
			.map(|general_name| match general_name {
				x509_parser::extensions::GeneralName::URI(uri) => *uri,
				_ => panic!("unexpected general name type"),
			})
			.collect::<Vec<_>>();

		// We should find the expected URIs.
		assert_eq!(
			uris,
			&[
				"http://example.com/crl.der",
				"http://crls.example.com/1234",
				"ldap://example.com/crl.der"
			]
		);
	}
}
