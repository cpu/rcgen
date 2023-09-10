use std::collections::BTreeMap;

use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, Tag};

use crate::oid::OID_AUTHORITY_KEY_IDENTIFIER;
use crate::Certificate;

use crate::RcgenError;

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
