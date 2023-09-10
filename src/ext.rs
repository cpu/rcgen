use std::collections::BTreeMap;
use std::net::IpAddr;

use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, Tag};

use crate::key_pair::PublicKeyData;
use crate::oid::{
	OID_AUTHORITY_KEY_IDENTIFIER, OID_BASIC_CONSTRAINTS, OID_CRL_DISTRIBUTION_POINTS,
	OID_EXT_KEY_USAGE, OID_KEY_USAGE, OID_NAME_CONSTRAINTS, OID_SUBJECT_ALT_NAME,
	OID_SUBJECT_KEY_IDENTIFIER,
};
use crate::RcgenError;
use crate::{
	write_distinguished_name, BasicConstraints, Certificate, CertificateParams,
	CrlDistributionPoint, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyUsagePurpose,
	NameConstraints, SanType,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Criticality {
	Critical,
	NonCritical,
}

#[derive(Clone, Debug)]
pub(crate) struct Extension {
	oid: ObjectIdentifier,
	criticality: Criticality,
	der_value: Vec<u8>,
}

impl Extension {
	pub(crate) fn write_der(&self, writer: DERWriter) {
		// Extension specification:
		//    Extension  ::=  SEQUENCE  {
		//         extnID      OBJECT IDENTIFIER,
		//         critical    BOOLEAN DEFAULT FALSE,
		//         extnValue   OCTET STRING
		//                     -- contains the DER encoding of an ASN.1 value
		//                     -- corresponding to the extension type identified
		//                     -- by extnID
		//         }
		writer.write_sequence(|writer| {
			writer.next().write_oid(&self.oid);
			writer
				.next()
				.write_bool(matches!(self.criticality, Criticality::Critical));
			writer.next().write_bytes(&self.der_value);
		})
	}
}

#[derive(Default)]
pub(crate) struct Extensions(BTreeMap<ObjectIdentifier, Extension>);

impl Extensions {
	pub(crate) fn add_extension(&mut self, extension: Extension) -> Result<(), RcgenError> {
		if self.0.get(&extension.oid).is_some() {
			return Err(RcgenError::DuplicateExtension(extension.oid.to_string()));
		}

		self.0.insert(extension.oid.clone(), extension);
		Ok(())
	}

	pub(crate) fn iter(self: &Self) -> impl Iterator<Item = &Extension> {
		self.0.values()
	}
}

/// An X.509v3 authority key identifier extension according to
/// [RFC 5280 4.2.1.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1).
pub(crate) fn authority_key_identifier(cert: &Certificate) -> Extension {
	Extension {
		oid: ObjectIdentifier::from_slice(OID_AUTHORITY_KEY_IDENTIFIER),
		// Conforming CAs MUST mark this extension as non-critical.
		criticality: Criticality::NonCritical,
		der_value: yasna::construct_der(|writer| {
			/*
				AuthorityKeyIdentifier ::= SEQUENCE {
					   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
					   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
					   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

				KeyIdentifier ::= OCTET STRING
			*/
			writer.write_sequence(|writer| {
				writer
					.next()
					.write_tagged_implicit(Tag::context(0), |writer| {
						writer.write_bytes(cert.get_key_identifier().as_ref())
					})
			});
		}),
	}
}

/// An X.509v3 subject alternative name extension according to
/// [RFC 5280 4.2.1.6](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6).
pub(crate) fn subject_alternative_names(names: &Vec<SanType>) -> Extension {
	Extension {
		oid: ObjectIdentifier::from_slice(OID_SUBJECT_ALT_NAME),
		// TODO(XXX): For now we mark the SAN extension as non-critical, matching the pre-existing
		// 			  handling, however per 5280 this extension's criticality is determined based
		//            on whether or not the subject contains an empty sequence. If it does, the
		//            SAN MUST be critical. If it has a non-empty subject distinguished name,
		//            the SAN SHOULD be non-critical.
		criticality: Criticality::NonCritical,
		der_value: yasna::construct_der(|writer| {
			/*
			   SubjectAltName ::= GeneralNames
			   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
			*/
			writer.write_sequence(|writer| {
				for san in names {
					writer.next().write_tagged_implicit(
						Tag::context(san.tag()),
						|writer| match san {
							SanType::Rfc822Name(name)
							| SanType::DnsName(name)
							| SanType::URI(name) => writer.write_ia5_string(&name),
							SanType::IpAddress(IpAddr::V4(addr)) => {
								writer.write_bytes(&addr.octets())
							},
							SanType::IpAddress(IpAddr::V6(addr)) => {
								writer.write_bytes(&addr.octets())
							},
						},
					);
				}
			});
		}),
	}
}

/// An X.509v3 key usage extension according to
/// [RFC 5280 4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3).
pub(crate) fn key_usage(usages: &Vec<KeyUsagePurpose>) -> Extension {
	Extension {
		oid: ObjectIdentifier::from_slice(OID_KEY_USAGE),
		// When present, conforming CAs SHOULD mark this extension as critical.
		criticality: Criticality::Critical,
		der_value: yasna::construct_der(|writer| {
			/*
			   KeyUsage ::= BIT STRING {
				  digitalSignature        (0),
				  nonRepudiation          (1), -- recent editions of X.509 have
									   -- renamed this bit to contentCommitment
				  keyEncipherment         (2),
				  dataEncipherment        (3),
				  keyAgreement            (4),
				  keyCertSign             (5),
				  cRLSign                 (6),
				  encipherOnly            (7),
				  decipherOnly            (8) }
			*/
			let mut bits: u16 = 0;

			for entry in usages.iter() {
				// Map the index to a value
				let index = match entry {
					KeyUsagePurpose::DigitalSignature => 0,
					KeyUsagePurpose::ContentCommitment => 1,
					KeyUsagePurpose::KeyEncipherment => 2,
					KeyUsagePurpose::DataEncipherment => 3,
					KeyUsagePurpose::KeyAgreement => 4,
					KeyUsagePurpose::KeyCertSign => 5,
					KeyUsagePurpose::CrlSign => 6,
					KeyUsagePurpose::EncipherOnly => 7,
					KeyUsagePurpose::DecipherOnly => 8,
				};

				bits |= 1 << index;
			}

			// Compute the 1-based most significant bit
			let msb = 16 - bits.leading_zeros();
			let nb = if msb <= 8 { 1 } else { 2 };

			let bits = bits.reverse_bits().to_be_bytes();

			// Finally take only the bytes != 0
			let bits = &bits[..nb];

			writer.write_bitvec_bytes(&bits, msb as usize)
		}),
	}
}

/// An X.509v3 extended key usage extension according to
/// [RFC 5280 4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12).
pub(crate) fn extended_key_usage(usages: &Vec<ExtendedKeyUsagePurpose>) -> Extension {
	Extension {
		oid: ObjectIdentifier::from_slice(OID_EXT_KEY_USAGE),
		// This extension MAY, at the option of the certificate issuer, be
		// either critical or non-critical.
		criticality: Criticality::NonCritical,
		der_value: yasna::construct_der(|writer| {
			/*
				  ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
				  KeyPurposeId ::= OBJECT IDENTIFIER
			*/
			writer.write_sequence(|writer| {
				for usage in usages.iter() {
					let oid = ObjectIdentifier::from_slice(usage.oid());
					writer.next().write_oid(&oid);
				}
			});
		}),
	}
}

/// An X.509v3 name constraints extension according to
/// [RFC 5280 4.2.1.10](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10).
pub(crate) fn name_constraints(constraints: &NameConstraints) -> Extension {
	fn write_general_subtrees(writer: DERWriter, tag: u64, general_subtrees: &[GeneralSubtree]) {
		/*
			GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

			GeneralSubtree ::= SEQUENCE {
				  base                    GeneralName,
				  minimum         [0]     BaseDistance DEFAULT 0,
				  maximum         [1]     BaseDistance OPTIONAL }

			BaseDistance ::= INTEGER (0..MAX)
		*/
		writer.write_tagged_implicit(Tag::context(tag), |writer| {
			writer.write_sequence(|writer| {
				for subtree in general_subtrees.iter() {
					writer.next().write_sequence(|writer| {
						writer.next().write_tagged_implicit(
							Tag::context(subtree.tag()),
							|writer| match subtree {
								GeneralSubtree::Rfc822Name(name)
								| GeneralSubtree::DnsName(name) => writer.write_ia5_string(name),
								GeneralSubtree::DirectoryName(name) => {
									write_distinguished_name(writer, name)
								},
								GeneralSubtree::IpAddress(subnet) => {
									writer.write_bytes(&subnet.to_bytes())
								},
							},
						);
						// minimum must be 0 (the default) and maximum must be absent
					});
				}
			});
		});
	}

	Extension {
		oid: ObjectIdentifier::from_slice(OID_NAME_CONSTRAINTS),
		// Conforming CAs MUST mark this extension as critical
		criticality: Criticality::Critical,
		der_value: yasna::construct_der(|writer| {
			/*
				NameConstraints ::= SEQUENCE {
					  permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
					  excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
			*/
			writer.write_sequence(|writer| {
				if !constraints.permitted_subtrees.is_empty() {
					write_general_subtrees(writer.next(), 0, &constraints.permitted_subtrees);
				}
				if !constraints.excluded_subtrees.is_empty() {
					write_general_subtrees(writer.next(), 1, &constraints.excluded_subtrees);
				}
			});
		}),
	}
}

/// An X.509v3 CRL distribution points extension according to
/// [RFC 5280 4.2.1.13](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13).
pub(crate) fn crl_distribution_points(
	crl_distribution_points: &Vec<CrlDistributionPoint>,
) -> Extension {
	Extension {
		oid: ObjectIdentifier::from_slice(OID_CRL_DISTRIBUTION_POINTS),
		// The extension SHOULD be non-critical
		criticality: Criticality::NonCritical,
		der_value: yasna::construct_der(|writer| {
			writer.write_sequence(|writer| {
				for distribution_point in crl_distribution_points {
					distribution_point.write_der(writer.next());
				}
			})
		}),
	}
}

/// An X.509v3 subject key identifier extension according to
/// [RFC 5280 4.2.1.2](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2).
pub(crate) fn subject_key_identifier<K: PublicKeyData>(
	params: &CertificateParams,
	pub_key: &K,
) -> Extension {
	Extension {
		oid: ObjectIdentifier::from_slice(OID_SUBJECT_KEY_IDENTIFIER),
		// Conforming CAs MUST mark this extension as non-critical.
		criticality: Criticality::NonCritical,
		der_value: yasna::construct_der(|writer| {
			// SubjectKeyIdentifier ::= KeyIdentifier
			// KeyIdentifier ::= OCTET STRING
			writer.write_bytes(&params.key_identifier(pub_key));
		}),
	}
}

/// An X.509v3 basic constraints extension according to
/// [RFC 5280 4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9).
pub(crate) fn basic_constraints(is_ca: &IsCa) -> Extension {
	Extension {
		oid: ObjectIdentifier::from_slice(OID_BASIC_CONSTRAINTS),
		// Conforming CAs MUST include this extension in all CA certificates
		// that contain public keys used to validate digital signatures on
		// certificates and MUST mark the extension as critical in such
		// certificates
		criticality: Criticality::Critical,
		der_value: yasna::construct_der(|writer| {
			/*
				BasicConstraints ::= SEQUENCE {
				  cA                      BOOLEAN DEFAULT FALSE,
				  pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
			*/
			writer.write_sequence(|writer| {
				writer.next().write_bool(matches!(is_ca, IsCa::Ca(_)));
				if let IsCa::Ca(BasicConstraints::Constrained(path_len_constraint)) = is_ca {
					writer.next().write_u8(*path_len_constraint);
				}
			});
		}),
	}
}
