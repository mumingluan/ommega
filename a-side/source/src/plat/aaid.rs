use der::asn1::{OctetString, SetOfVec};

#[derive(der::Sequence, Debug)]
pub struct AttestationApplicationId {
    pub package_info_records: SetOfVec<PackageInfoRecord>,
    pub signature_digests: SetOfVec<OctetString>,
}

#[derive(der::Sequence, der::ValueOrd, Debug)]
pub struct PackageInfoRecord {
    pub package_name: OctetString,
    pub version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    #[test]
    fn synthesized_application_id_contains_both_required_sets() {
        let decoded = AttestationApplicationId::from_der(
            kmr_common::consts::EMPTY_ATTESTATION_APPLICATION_ID_DER,
        )
        .expect("the relay must accept the synthesized application ID");
        assert!(decoded.package_info_records.is_empty());
        assert!(decoded.signature_digests.is_empty());
        assert!(AttestationApplicationId::from_der(&[0x30, 0x00]).is_err());
    }
}
