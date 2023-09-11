#[cfg(feature = "x509-parser")]
use crate::{CustomExtension, DistinguishedName, SanType};
#[cfg(feature = "pem")]
use pem::Pem;
use std::hash::Hash;

use crate::{Certificate, CertificateParams, PublicKeyData, RcgenError, SignatureAlgorithm};

/// A public key, extracted from a CSR
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
	raw: Vec<u8>,
	alg: &'static SignatureAlgorithm,
}

impl PublicKeyData for PublicKey {
	fn alg(&self) -> &SignatureAlgorithm {
		self.alg
	}

	fn raw_bytes(&self) -> &[u8] {
		&self.raw
	}
}

/// Data for a certificate signing request
pub struct CertificateSigningRequest {
	/// Parameters for the certificate to be signed.
	pub params: CertificateParams,
	/// Public key to include in the certificate signing request.
	pub public_key: PublicKey,
}

impl CertificateSigningRequest {
	/// Parse a certificate signing request from the ASCII PEM format
	///
	/// See [`from_der`](Self::from_der) for more details.
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_pem(pem_str: &str) -> Result<Self, RcgenError> {
		let csr = pem::parse(pem_str).or(Err(RcgenError::CouldNotParseCertificationRequest))?;
		Self::from_der(csr.contents())
	}

	/// Parse a certificate signing request from DER-encoded bytes
	///
	/// Currently, this only supports the `Subject Alternative Name` extension.
	/// On encountering other extensions, this function will return an error.
	#[cfg(feature = "x509-parser")]
	pub fn from_der(csr: &[u8]) -> Result<Self, RcgenError> {
		use x509_parser::prelude::FromDer;
		let csr = x509_parser::certification_request::X509CertificationRequest::from_der(csr)
			.map_err(|_| RcgenError::CouldNotParseCertificationRequest)?
			.1;
		csr.verify_signature()
			.map_err(|_| RcgenError::RingUnspecified)?;
		let alg_oid = csr
			.signature_algorithm
			.algorithm
			.iter()
			.ok_or(RcgenError::CouldNotParseCertificationRequest)?
			.collect::<Vec<_>>();
		let alg = SignatureAlgorithm::from_oid(&alg_oid)?;

		let info = &csr.certification_request_info;
		let mut params = CertificateParams::default();
		params.alg = alg;
		params.distinguished_name = DistinguishedName::from_name(&info.subject)?;
		let raw = info.subject_pki.subject_public_key.data.to_vec();

		// Pull out the extension requests attributes from the CSR.
		// Note: we avoid using csr.requested_extensions() here because it maps to the parsed
		// extension value and we want the raw extension value to handle unknown extensions
		// ourselves.
		let requested_exts = csr
			.certification_request_info
			.iter_attributes()
			.filter_map(|attr| {
				if let x509_parser::prelude::ParsedCriAttribute::ExtensionRequest(requested) =
					&attr.parsed_attribute()
				{
					Some(requested.extensions.iter().collect::<Vec<_>>())
				} else {
					None
				}
			})
			.flatten()
			.collect::<Vec<_>>();

		if !requested_exts.is_empty() {
			for ext in requested_exts {
				let supported = match ext.parsed_extension() {
					x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
						for name in &san.general_names {
							params
								.subject_alt_names
								.push(SanType::try_from_general(name)?);
						}
						true
					},
					x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(ski) => {
						params.key_identifier = ski.0.to_vec();
						true
					},
					_ => false,
				};
				if !supported {
					params.custom_extensions.push(CustomExtension {
						oid: ext.oid.iter().unwrap().collect(),
						critical: ext.critical,
						content: ext.value.to_vec(),
					})
				}
			}
		}

		// Not yet handled:
		// * is_ca
		// * extended_key_usages
		// * name_constraints
		// and any other extensions.

		Ok(Self {
			params,
			public_key: PublicKey { alg, raw },
		})
	}
	/// Serializes the requested certificate, signed with another certificate's key, in binary DER format
	pub fn serialize_der_with_signer(&self, ca: &Certificate) -> Result<Vec<u8>, RcgenError> {
		self.params.serialize_der_with_signer(&self.public_key, ca)
	}
	/// Serializes the requested certificate, signed with another certificate's key, to the ASCII PEM format
	#[cfg(feature = "pem")]
	pub fn serialize_pem_with_signer(&self, ca: &Certificate) -> Result<String, RcgenError> {
		let contents = self
			.params
			.serialize_der_with_signer(&self.public_key, ca)?;
		let p = Pem::new("CERTIFICATE", contents);
		Ok(pem::encode_config(&p, crate::ENCODE_CONFIG))
	}
}
