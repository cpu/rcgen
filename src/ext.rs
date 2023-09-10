use std::collections::BTreeMap;
use std::net::IpAddr;

use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, Tag};

use crate::oid::{OID_AUTHORITY_KEY_IDENTIFIER, OID_SUBJECT_ALT_NAME};
use crate::Error;
use crate::{Certificate, SanType};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Criticality {
	#[allow(dead_code)] // TODO: remove once first critical ext ported to this mod.
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
	pub(crate) fn add_extension(&mut self, extension: Extension) -> Result<(), Error> {
		if self.0.get(&extension.oid).is_some() {
			return Err(Error::DuplicateExtension(extension.oid.to_string()));
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
