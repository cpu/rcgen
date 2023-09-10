use std::collections::BTreeMap;

use yasna::models::ObjectIdentifier;
use yasna::DERWriter;

use crate::Error;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // TODO: Remove once used in lib.rs
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
	#[allow(dead_code)] // TODO: Remove once used in lib.rs
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
