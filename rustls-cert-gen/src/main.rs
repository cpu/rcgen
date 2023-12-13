#![allow(clippy::complexity, clippy::style, clippy::pedantic)]

use rcgen::{date_time_ymd, Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut params: CertificateParams = Default::default();
	params.not_before = date_time_ymd(1975, 01, 01);
	params.not_after = date_time_ymd(4096, 01, 01);
	params.distinguished_name = DistinguishedName::new();
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params
		.distinguished_name
		.push(DnType::CommonName, "Master Cert");
	params.subject_alt_names = vec![
		SanType::DnsName("crabs.crabs".to_string()),
		SanType::DnsName("localhost".to_string()),
	];

	let (cert, key_pair) = Certificate::generate_self_signed(params)?;

	let pem_serialized = cert.pem();
	let pem = pem::parse(&pem_serialized)?;
	let der_serialized = pem.contents();
	println!("{pem_serialized}");
	println!("{}", key_pair.serialize_pem());
	std::fs::create_dir_all("certs/")?;
	fs::write("certs/cert.pem", &pem_serialized.as_bytes())?;
	fs::write("certs/cert.der", &der_serialized)?;
	fs::write("certs/key.pem", key_pair.serialize_pem().as_bytes())?;
	fs::write("certs/key.der", key_pair.serialize_der())?;
	Ok(())
}
