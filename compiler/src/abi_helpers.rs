use noirc_abi::{AbiType, MAIN_RETURN_NAME, input_parser::InputValue};
use std::collections::BTreeMap;
use tracing::warn;

use mavros_artifacts::{InputValueOrdered, WitnessManifest};

/// Converts a BTreeMap of input values (keyed by parameter name) into a Vec of
/// InputValueOrdered, ordered according to the Noir ABI parameter order.
///
/// When the ABI declares a return value, the guard slot and the declared return
/// are appended after the regular parameters. An input map without a `return`
/// key sets the guard to 0 and zero-fills the declared return, which disables
/// the return-value check (see `prepare_entry_point`); that is warned about
/// rather than rejected, so a misspelled key cannot silently disable the check.
///
/// Errors when a declared parameter has no value in the map.
pub fn ordered_params_from_btreemap(
    abi: &noirc_abi::Abi,
    unordered_params: &BTreeMap<String, InputValue>,
) -> Result<Vec<InputValueOrdered>, String> {
    let mut ordered_params = Vec::new();
    for param in &abi.parameters {
        let param_value = unordered_params
            .get(&param.name)
            .ok_or_else(|| format!("inputs do not supply parameter `{}`", param.name))?;

        ordered_params.push(ordered_param(&param.typ, param_value)?);
    }

    if let Some(return_type) = &abi.return_type {
        match unordered_params.get(MAIN_RETURN_NAME) {
            Some(return_value) => {
                ordered_params.push(field_param(1));
                ordered_params.push(ordered_param(&return_type.abi_type, return_value)?);
            }
            None => {
                warn!(message = %format!(
                    "the ABI declares a return value but the inputs do not supply \
                     `{MAIN_RETURN_NAME}`; the return-value check is disabled (guard = 0)"
                ));
                ordered_params.push(field_param(0));
                ordered_params.push(zero_param(&return_type.abi_type));
            }
        }
    }

    let flattened = crate::vm::interpreter::flattened_param_count(&ordered_params);
    if flattened != flattened_io_count(abi) {
        return Err("ordered params do not flatten to the ABI's io count".to_string());
    }
    Ok(ordered_params)
}

pub fn guard_layout(abi: &noirc_abi::Abi) -> Option<(usize, usize)> {
    abi.return_type.as_ref().map(|ret| {
        (
            1 + abi.field_count() as usize,
            ret.abi_type.field_count() as usize,
        )
    })
}

/// Checks that the named witness columns hold the corresponding input fields.
/// `manifest` must already be validated against the R1CS.
pub fn check_witness_manifest(
    manifest: &WitnessManifest,
    ordered_params: &[InputValueOrdered],
    wit_pre_comm: &[mavros_artifacts::Field],
) -> Result<(), String> {
    let blob = crate::vm::interpreter::flatten_param_vec(ordered_params);
    if blob.len() != manifest.entry_blob_field_count {
        return Err(format!(
            "inputs flatten to {} fields but the manifest expects an entry blob of {}",
            blob.len(),
            manifest.entry_blob_field_count
        ));
    }
    let check = |what: &str, column_start: usize, blob_offset: usize, len: usize| {
        for j in 0..len {
            let column = column_start + j;
            let expected = blob.get(blob_offset + j).ok_or_else(|| {
                format!(
                    "{what}: blob slot {} is past the end of the inputs",
                    blob_offset + j
                )
            })?;
            match wit_pre_comm.get(column) {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(format!(
                        "{what}: witness[{column}] holds {actual} but entry blob slot {} is \
                         {expected}",
                        blob_offset + j
                    ));
                }
                None => {
                    return Err(format!(
                        "{what}: witness has no column {column} (pre-commitment witness has {} \
                         values)",
                        wit_pre_comm.len()
                    ));
                }
            }
        }
        Ok(())
    };
    for param in &manifest.parameters {
        if let Some(start) = param.column_start {
            check(
                &format!("parameter `{}`", param.name),
                start,
                param.blob_offset,
                param.width,
            )?;
        }
    }
    let mut blob_offset: usize = manifest.parameters.iter().map(|param| param.width).sum();
    if let Some(guard) = manifest.guard_column {
        check("return guard", guard, blob_offset, 1)?;
        blob_offset += 1;
    }
    if let Some(ret) = manifest.returns {
        check("declared return", ret.column_start, blob_offset, ret.len)?;
    }
    Ok(())
}

pub fn flattened_io_count(abi: &noirc_abi::Abi) -> usize {
    let returns = abi
        .return_type
        .as_ref()
        .map_or(0, |ret| 1 + ret.abi_type.field_count() as usize);
    abi.field_count() as usize + returns
}

fn field_param(value: u64) -> InputValueOrdered {
    InputValueOrdered::Field(ark_bn254::Fr::from(value)) // FIELD-ASSUMPTION: L1-direct-ref (2 sites)
}

fn zero_param(abi_type: &AbiType) -> InputValueOrdered {
    match abi_type {
        AbiType::Array { typ, length } => {
            InputValueOrdered::Vec((0..*length).map(|_| zero_param(typ)).collect())
        }
        AbiType::Struct { fields, .. } => InputValueOrdered::Struct(
            fields
                .iter()
                .map(|(name, ty)| (name.clone(), zero_param(ty)))
                .collect(),
        ),
        AbiType::Tuple { fields } => InputValueOrdered::Struct(
            fields
                .iter()
                .enumerate()
                .map(|(idx, ty)| (idx.to_string(), zero_param(ty)))
                .collect(),
        ),
        AbiType::String { length } => {
            InputValueOrdered::Vec((0..*length).map(|_| field_param(0)).collect())
        }
        _ => field_param(0),
    }
}

fn ordered_param(abi_type: &AbiType, value: &InputValue) -> Result<InputValueOrdered, String> {
    Ok(match (value, abi_type) {
        (InputValue::Field(elem), _) => InputValueOrdered::Field(elem.into_repr()),
        (InputValue::Vec(vec_elements), AbiType::Array { typ, length }) => {
            if vec_elements.len() != *length as usize {
                return Err("Array value length does not match ABI array length".to_string());
            }
            InputValueOrdered::Vec(
                vec_elements
                    .iter()
                    .map(|elem| ordered_param(typ, elem))
                    .collect::<Result<_, _>>()?,
            )
        }
        (InputValue::Struct(object), AbiType::Struct { fields, .. }) => InputValueOrdered::Struct(
            fields
                .iter()
                .map(|(field_name, field_type)| {
                    let field_value = object
                        .get(field_name)
                        .ok_or_else(|| "Field not found in struct".to_string())?;
                    Ok((field_name.clone(), ordered_param(field_type, field_value)?))
                })
                .collect::<Result<Vec<_>, String>>()?,
        ),
        (InputValue::String(string), AbiType::String { length }) => {
            let bytes = string.as_bytes();
            if bytes.len() != *length as usize {
                return Err("String value length does not match ABI string length".to_string());
            }
            InputValueOrdered::Vec(
                bytes
                    .iter()
                    .map(|byte| InputValueOrdered::Field(ark_bn254::Fr::from(*byte as u64)))
                    .collect(),
            )
        }
        (InputValue::String(_string), _) => {
            return Err("String input did not match ABI string type".to_string());
        }
        (InputValue::Vec(vec_elements), AbiType::Tuple { fields }) => {
            if vec_elements.len() != fields.len() {
                return Err("Tuple value length does not match ABI tuple field count".to_string());
            }
            InputValueOrdered::Struct(
                fields
                    .iter()
                    .zip(vec_elements.iter())
                    .enumerate()
                    .map(|(idx, (field_type, field_value))| {
                        Ok((idx.to_string(), ordered_param(field_type, field_value)?))
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            )
        }
        _ => {
            return Err("value should have already been checked to match abi type".to_string());
        }
    })
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use noirc_abi::{Abi, AbiParameter, AbiReturnType, AbiType, AbiVisibility};

    use super::*;

    fn string_abi(param_names: &[&str], has_return: bool) -> Abi {
        let string = AbiType::String { length: 2 };
        Abi {
            parameters: param_names
                .iter()
                .map(|name| AbiParameter {
                    name: (*name).to_string(),
                    typ: string.clone(),
                    visibility: AbiVisibility::Private,
                })
                .collect(),
            return_type: has_return.then(|| AbiReturnType {
                abi_type: string,
                visibility: AbiVisibility::Public,
            }),
            error_types: Default::default(),
        }
    }

    fn guard_value(params: &[InputValueOrdered], index: usize) -> u64 {
        match &params[index] {
            InputValueOrdered::Field(f) => {
                if *f == ark_bn254::Fr::from(0u64) {
                    0
                } else {
                    1
                }
            }
            other => panic!("guard slot is not a field: {other:?}"),
        }
    }

    #[test]
    fn missing_parameter_is_an_error() {
        let abi = string_abi(&["x"], false);
        let error = ordered_params_from_btreemap(&abi, &BTreeMap::new()).unwrap_err();
        assert!(
            error.contains("`x`"),
            "error does not name the parameter: {error}"
        );
    }

    #[test]
    fn missing_return_key_sets_guard_to_zero_and_zero_fills() {
        let abi = string_abi(&[], true);
        let params = ordered_params_from_btreemap(&abi, &BTreeMap::new()).unwrap();
        // Guard slot, then the zero-filled two-field declared return.
        assert_eq!(params.len(), 2);
        assert_eq!(guard_value(&params, 0), 0);
        assert_eq!(
            params[1],
            InputValueOrdered::Vec(vec![
                InputValueOrdered::Field(ark_bn254::Fr::from(0u64)),
                InputValueOrdered::Field(ark_bn254::Fr::from(0u64)),
            ])
        );
    }

    #[test]
    fn supplied_return_key_sets_guard_to_one() {
        let abi = string_abi(&[], true);
        let inputs = BTreeMap::from([(
            MAIN_RETURN_NAME.to_string(),
            InputValue::String("ab".to_string()),
        )]);
        let params = ordered_params_from_btreemap(&abi, &inputs).unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(guard_value(&params, 0), 1);
    }

    fn string_manifest(abi: &Abi) -> WitnessManifest {
        use mavros_artifacts::{ManifestParam, ParamVisibility, ReturnSlot};
        let parameters = abi
            .parameters
            .iter()
            .enumerate()
            .map(|(i, param)| ManifestParam {
                name: param.name.clone(),
                visibility: if param.visibility == AbiVisibility::Public {
                    ParamVisibility::Public
                } else {
                    ParamVisibility::Private
                },
                blob_offset: 2 * i,
                width: 2,
                column_start: Some(1 + 2 * i),
            })
            .collect::<Vec<_>>();
        let after_params = 2 * parameters.len();
        WitnessManifest {
            entry_blob_field_count: after_params + 3,
            parameters,
            guard_column: Some(1 + after_params),
            returns: Some(ReturnSlot {
                column_start: 2 + after_params,
                len: 2,
                visibility: ParamVisibility::Public,
            }),
            challenges: vec![],
            pre_commitment_size: after_params + 5,
            witness_count: after_params + 5,
            constraint_count: 0,
        }
    }

    #[test]
    fn witness_manifest_check_compares_every_named_column() {
        let abi = string_abi(&["x", "y"], true);
        let inputs = BTreeMap::from([
            ("x".to_string(), InputValue::String("ab".to_string())),
            ("y".to_string(), InputValue::String("cd".to_string())),
            (
                MAIN_RETURN_NAME.to_string(),
                InputValue::String("ef".to_string()),
            ),
        ]);
        let params = ordered_params_from_btreemap(&abi, &inputs).unwrap();
        let manifest = string_manifest(&abi);
        let field = |byte: u8| ark_bn254::Fr::from(byte as u64);
        // witness[0] = 1, then x, y, guard = 1, return.
        let mut witness = vec![ark_bn254::Fr::from(1u64)];
        witness.extend(b"abcd".iter().map(|b| field(*b)));
        witness.push(ark_bn254::Fr::from(1u64));
        witness.extend(b"ef".iter().map(|b| field(*b)));
        witness.push(ark_bn254::Fr::from(99u64));
        assert_eq!(check_witness_manifest(&manifest, &params, &witness), Ok(()));

        let mut wrong = witness.clone();
        wrong[3] = field(b'z');
        let error = check_witness_manifest(&manifest, &params, &wrong).unwrap_err();
        assert!(
            error.contains("parameter `y`") && error.contains("witness[3]"),
            "{error}"
        );

        let mut wrong = witness.clone();
        wrong[5] = ark_bn254::Fr::from(0u64);
        let error = check_witness_manifest(&manifest, &params, &wrong).unwrap_err();
        assert!(error.contains("return guard"), "{error}");
        let mut wrong = witness.clone();
        wrong.swap(6, 7);
        let error = check_witness_manifest(&manifest, &params, &wrong).unwrap_err();
        assert!(error.contains("declared return"), "{error}");

        let error = check_witness_manifest(&manifest, &params, &witness[..4]).unwrap_err();
        assert!(error.contains("no column"), "{error}");

        let error = check_witness_manifest(&manifest, &params[..1], &witness).unwrap_err();
        assert!(error.contains("entry blob"), "{error}");
    }
}
