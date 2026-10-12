//! Witness metadata and the versioned `r1cs.bin` format.
//!
//! ```text
//! [ MAVR1CS\0 (8 bytes) ][ format version: u32 LE ][ field: u32 LE ][ bincode { manifest, r1cs } ]
//! ```
//!
//! Bump [`R1CS_ARTIFACT_FORMAT_VERSION`] when changing the serialized manifest, R1CS or layouts.

use serde::{Deserialize, Serialize};

use crate::{FieldId, R1CS};

/// The first column an entry-point value can occupy; column 0 is the constant one.
pub const ENTRY_BLOB_COLUMN_BASE: usize = 1;

/// Visibility of an entry-point parameter or return, as declared in the Noir ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParamVisibility {
    Public,
    Private,
    DataBus,
}

/// Where one ABI parameter sits in the input blob and in the witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestParam {
    pub name: String,
    pub visibility: ParamVisibility,
    /// Index of the parameter's first field in the entry blob.
    pub blob_offset: usize,
    /// Number of flattened fields the parameter occupies.
    pub width: usize,
    /// First witness column of the parameter, or `None` if the compiler elided its columns.
    pub column_start: Option<usize>,
}

/// Where the declared return sits in the witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReturnSlot {
    pub column_start: usize,
    pub len: usize,
    pub visibility: ParamVisibility,
}

/// One verifier challenge in the post-commitment witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeSlot {
    /// Absolute witness index.
    pub witness_index: usize,
    /// Offset from the start of the post-commitment witness (w2).
    pub w2_offset: usize,
}

/// The entry point's witness layout, as laid out by the compiler.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessManifest {
    /// Number of input fields the VM entry point expects.
    pub entry_blob_field_count: usize,
    pub parameters: Vec<ManifestParam>,
    /// Column of the return guard, present exactly when the ABI declares a return.
    pub guard_column: Option<usize>,
    pub returns: Option<ReturnSlot>,
    pub challenges: Vec<ChallengeSlot>,
    /// Number of witness values committed before the challenges (the w1/w2 boundary).
    pub pre_commitment_size: usize,
    pub witness_count: usize,
    pub constraint_count: usize,
}

impl WitnessManifest {
    /// Checks witness totals and the parameter, guard, return and challenge positions.
    pub fn validate(&self, r1cs: &R1CS) -> Result<(), String> {
        let layout = r1cs.witness_layout;
        let check = |ok: bool, what: &str| {
            ok.then_some(())
                .ok_or_else(|| format!("witness manifest disagrees with the R1CS: {what}"))
        };
        let add = |start: usize, len: usize, what: &str| {
            start.checked_add(len).ok_or_else(|| {
                format!("witness manifest disagrees with the R1CS: {what} overflows")
            })
        };
        let pre_commitment_size = add(
            layout.algebraic_size,
            layout.multiplicities_size,
            "pre-commitment size",
        )?;
        let witness_count = [
            layout.challenges_size,
            layout.tables_data_size,
            layout.lookups_data_size,
        ]
        .into_iter()
        .try_fold(pre_commitment_size, |size, len| {
            add(size, len, "witness count")
        })?;
        check(self.witness_count == witness_count, "witness count")?;
        check(
            self.constraint_count == r1cs.constraints.len(),
            "constraint count",
        )?;
        check(
            self.pre_commitment_size == pre_commitment_size,
            "pre-commitment size",
        )?;
        check(self.guard_column == layout.guard_index, "guard column")?;
        check(
            self.guard_column.is_some() == self.returns.is_some(),
            "return guard presence",
        )?;
        check(
            self.returns.map_or(0, |ret| ret.len) == layout.return_len,
            "return length",
        )?;
        check(
            self.challenges.len() == layout.challenges_size,
            "challenge count",
        )?;
        for (i, challenge) in self.challenges.iter().enumerate() {
            check(
                challenge.w2_offset == i
                    && challenge.witness_index
                        == add(pre_commitment_size, i, "challenge position")?,
                "challenge positions",
            )?;
        }

        let mut column = ENTRY_BLOB_COLUMN_BASE;
        for param in &self.parameters {
            check(
                param.blob_offset == column - ENTRY_BLOB_COLUMN_BASE,
                "parameter blob offset",
            )?;
            check(
                param.column_start.is_none_or(|start| start == column),
                "parameter column",
            )?;
            column = add(column, param.width, "parameter columns")?;
        }
        if let Some(guard) = self.guard_column {
            check(guard == column, "guard column position")?;
            column = add(column, 1, "guard column")?;
        }
        if let Some(ret) = self.returns {
            check(ret.column_start == column, "return column")?;
            column = add(column, ret.len, "return columns")?;
        }
        check(
            self.entry_blob_field_count == column - ENTRY_BLOB_COLUMN_BASE,
            "entry blob field count",
        )?;
        check(
            column <= layout.algebraic_size,
            "entry blob outside the algebraic section",
        )
    }
}

/// Leading bytes of a versioned `r1cs.bin`.
pub const R1CS_ARTIFACT_MAGIC: [u8; 8] = *b"MAVR1CS\0";
/// Format version this crate writes and the only one it reads.
pub const R1CS_ARTIFACT_FORMAT_VERSION: u32 = 1;

const HEADER_LEN: usize = R1CS_ARTIFACT_MAGIC.len() + 4 + 4;

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("r1cs.bin does not start with the MAVR1CS header, so it is not a Mavros R1CS artifact")]
    MissingHeader,
    #[error("unsupported r1cs.bin format version {0}; expected {R1CS_ARTIFACT_FORMAT_VERSION}")]
    UnsupportedVersion(u32),
    #[error("r1cs.bin names unknown field {0}")]
    UnknownField(u32),
    #[error("r1cs.bin body: {0}")]
    Body(#[from] bincode::Error),
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct Body {
    manifest: WitnessManifest,
    r1cs: R1CS,
}

/// The contents of a versioned `r1cs.bin`: the field, the witness manifest and the R1CS.
#[derive(Debug)]
pub struct R1CSArtifact {
    field: FieldId,
    body: Body,
}

impl R1CSArtifact {
    pub fn new(field: FieldId, manifest: WitnessManifest, r1cs: R1CS) -> Self {
        Self {
            field,
            body: Body { manifest, r1cs },
        }
    }

    pub fn field(&self) -> FieldId {
        self.field
    }

    pub fn manifest(&self) -> &WitnessManifest {
        &self.body.manifest
    }

    pub fn r1cs(&self) -> &R1CS {
        &self.body.r1cs
    }

    pub fn into_parts(self) -> (FieldId, WitnessManifest, R1CS) {
        (self.field, self.body.manifest, self.body.r1cs)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&R1CS_ARTIFACT_MAGIC);
        bytes.extend_from_slice(&R1CS_ARTIFACT_FORMAT_VERSION.to_le_bytes());
        let field_code = u32::try_from(self.field.code()).expect("field codes fit in u32");
        bytes.extend_from_slice(&field_code.to_le_bytes());
        bincode::serialize_into(&mut bytes, &self.body)?;
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < HEADER_LEN || bytes[..R1CS_ARTIFACT_MAGIC.len()] != R1CS_ARTIFACT_MAGIC {
            return Err(ArtifactError::MissingHeader);
        }
        let u32_at =
            |start: usize| u32::from_le_bytes(bytes[start..start + 4].try_into().expect("4 bytes"));
        let version = u32_at(R1CS_ARTIFACT_MAGIC.len());
        if version != R1CS_ARTIFACT_FORMAT_VERSION {
            return Err(ArtifactError::UnsupportedVersion(version));
        }
        let field_code = u32_at(R1CS_ARTIFACT_MAGIC.len() + 4);
        let field = FieldId::from_code(u64::from(field_code))
            .ok_or(ArtifactError::UnknownField(field_code))?;
        let body: Body = bincode::deserialize(&bytes[HEADER_LEN..])?;
        body.manifest
            .validate(&body.r1cs)
            .map_err(ArtifactError::Invalid)?;
        Ok(Self { field, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConstraintsLayout, WitnessLayout};

    fn r1cs() -> R1CS {
        R1CS {
            witness_layout: WitnessLayout {
                guard_index: Some(3),
                return_len: 1,
                algebraic_size: 6,
                multiplicities_size: 0,
                challenges_size: 0,
                tables_data_size: 0,
                lookups_data_size: 0,
            },
            constraints_layout: ConstraintsLayout {
                algebraic_size: 0,
                tables_data_size: 0,
                lookups_data_size: 0,
            },
            constraints: vec![],
        }
    }

    /// `fn main(x: Field, y: pub Field) -> pub Field`.
    fn manifest() -> WitnessManifest {
        WitnessManifest {
            entry_blob_field_count: 4,
            parameters: vec![
                ManifestParam {
                    name: "x".into(),
                    visibility: ParamVisibility::Private,
                    blob_offset: 0,
                    width: 1,
                    column_start: Some(1),
                },
                ManifestParam {
                    name: "y".into(),
                    visibility: ParamVisibility::Public,
                    blob_offset: 1,
                    width: 1,
                    column_start: Some(2),
                },
            ],
            guard_column: Some(3),
            returns: Some(ReturnSlot {
                column_start: 4,
                len: 1,
                visibility: ParamVisibility::Public,
            }),
            challenges: vec![],
            pre_commitment_size: 6,
            witness_count: 6,
            constraint_count: 0,
        }
    }

    fn round_trip(manifest: WitnessManifest, r1cs: R1CS) -> Result<R1CSArtifact, ArtifactError> {
        let bytes = R1CSArtifact::new(FieldId::Bn254, manifest, r1cs)
            .to_bytes()
            .unwrap();
        R1CSArtifact::from_bytes(&bytes)
    }

    #[test]
    fn artifact_round_trips() {
        let cases: [fn(&mut WitnessManifest, &mut R1CS); 4] = [
            |_, _| {},
            |m, r| {
                m.guard_column = None;
                m.returns = None;
                m.entry_blob_field_count = 2;
                r.witness_layout.guard_index = None;
                r.witness_layout.return_len = 0;
            },
            |m, r| {
                m.parameters[0].width = 0;
                m.parameters[1].blob_offset = 0;
                m.parameters[1].column_start = Some(1);
                m.guard_column = Some(2);
                m.returns.as_mut().unwrap().column_start = 3;
                m.returns.as_mut().unwrap().len = 0;
                m.entry_blob_field_count = 2;
                m.pre_commitment_size = 3;
                m.witness_count = 3;
                r.witness_layout.guard_index = Some(2);
                r.witness_layout.return_len = 0;
                r.witness_layout.algebraic_size = 3;
            },
            |m, _| m.parameters[0].column_start = None,
        ];
        for mutate in cases {
            let (mut m, mut r) = (manifest(), r1cs());
            mutate(&mut m, &mut r);
            let bytes = R1CSArtifact::new(FieldId::Bn254, m.clone(), r.clone())
                .to_bytes()
                .unwrap();
            assert!(bytes.starts_with(&R1CS_ARTIFACT_MAGIC));
            let decoded = R1CSArtifact::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.field(), FieldId::Bn254);
            assert_eq!(decoded.manifest(), &m);
            assert_eq!(
                decoded.r1cs().witness_layout.size(),
                r.witness_layout.size()
            );
        }
    }

    #[test]
    fn artifact_rejects_invalid_headers() {
        assert!(matches!(
            R1CSArtifact::from_bytes(&[]),
            Err(ArtifactError::MissingHeader)
        ));
        let mut bytes = R1CSArtifact::new(FieldId::Bn254, manifest(), r1cs())
            .to_bytes()
            .unwrap();
        assert!(matches!(
            R1CSArtifact::from_bytes(&bytes[..10]),
            Err(ArtifactError::MissingHeader)
        ));
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            R1CSArtifact::from_bytes(&bytes),
            Err(ArtifactError::UnsupportedVersion(2))
        ));
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            R1CSArtifact::from_bytes(&bytes),
            Err(ArtifactError::UnknownField(99))
        ));
    }

    #[test]
    fn artifact_rejects_inconsistent_entry_slots() {
        let cases: [fn(&mut WitnessManifest, &mut R1CS); 8] = [
            |m, _| m.parameters[1].blob_offset = 900,
            |m, _| m.parameters[1].column_start = Some(1),
            |m, _| m.parameters[0].column_start = Some(0),
            |m, _| m.returns.as_mut().unwrap().column_start = 1,
            |m, _| m.guard_column = Some(2),
            |m, r| {
                m.guard_column = Some(2);
                r.witness_layout.guard_index = Some(2);
            },
            |m, r| {
                m.returns = None;
                m.entry_blob_field_count = 2;
                r.witness_layout.return_len = 0;
            },
            |m, r| {
                m.pre_commitment_size = 4;
                m.witness_count = 4;
                r.witness_layout.algebraic_size = 4;
            },
        ];
        for (case, mutate) in cases.into_iter().enumerate() {
            let (mut m, mut r) = (manifest(), r1cs());
            mutate(&mut m, &mut r);
            assert!(
                matches!(round_trip(m, r), Err(ArtifactError::Invalid(_))),
                "entry slot case {case}"
            );
        }
    }

    #[test]
    fn artifact_rejects_overflowing_ranges_and_totals() {
        let cases: [fn(&mut WitnessManifest, &mut R1CS); 4] = [
            |m, _| m.parameters[0].width = usize::MAX,
            |_, r| r.witness_layout.multiplicities_size = usize::MAX,
            |_, r| r.witness_layout.lookups_data_size = usize::MAX,
            |m, r| {
                m.returns.as_mut().unwrap().len = usize::MAX;
                r.witness_layout.return_len = usize::MAX;
            },
        ];
        for (case, mutate) in cases.into_iter().enumerate() {
            let (mut m, mut r) = (manifest(), r1cs());
            mutate(&mut m, &mut r);
            assert!(
                matches!(round_trip(m, r), Err(ArtifactError::Invalid(_))),
                "overflow case {case}"
            );
        }
    }

    #[test]
    fn challenges_must_sit_at_the_layout_positions() {
        let (mut m, mut r) = (manifest(), r1cs());
        r.witness_layout.multiplicities_size = 2;
        r.witness_layout.challenges_size = 2;
        r.witness_layout.tables_data_size = 3;
        r.witness_layout.lookups_data_size = 4;
        m.pre_commitment_size = 8;
        m.witness_count = 17;
        m.challenges = vec![
            ChallengeSlot {
                witness_index: 8,
                w2_offset: 0,
            },
            ChallengeSlot {
                witness_index: 9,
                w2_offset: 1,
            },
        ];
        assert!(round_trip(m.clone(), r.clone()).is_ok());
        m.challenges[1].w2_offset = 0;
        assert!(matches!(round_trip(m, r), Err(ArtifactError::Invalid(_))));
    }
}
