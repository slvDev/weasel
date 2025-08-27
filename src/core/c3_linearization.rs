//! C3 Linearization Algorithm for Solidity Inheritance Resolution
//!
//! Implements the C3 linearization algorithm used by Solidity to determine
//! the Method Resolution Order (MRO) for multiple inheritance.
//!
//! Key differences from Python's C3:
//! - Solidity uses right-to-left ordering (most base-like to most derived)
//! - Direct bases are listed from "most base-like" to "most derived"

/// Performs C3 linearization for a contract with given direct bases
///
/// # Arguments
/// * `contract_name` - The name of the contract being linearized
/// * `direct_bases` - Direct base contracts in Solidity order (most base to most derived)
/// * `get_linearization` - Function to get linearization of a base contract
///
/// # Returns
/// * `Ok(Vec<String>)` - Linearized inheritance chain (most base to most derived)
/// * `Err(String)` - Error message if linearization fails
pub fn c3_linearize<F>(
    contract_name: &str,
    direct_bases: &[String],
    get_linearization: F,
) -> Result<Vec<String>, String>
where
    F: Fn(&str) -> Result<Vec<String>, String>,
{
    if direct_bases.is_empty() {
        // Base case: contract with no parents
        return Ok(vec![]);
    }

    // Get linearization for each parent
    let mut parent_linearizations = Vec::new();
    for base in direct_bases {
        let base_linearization = get_linearization(base)?;
        // Add the base itself to its linearization
        let mut full_linearization = vec![base.clone()];
        full_linearization.extend(base_linearization);
        parent_linearizations.push(full_linearization);
    }

    // Add the list of direct parents as the last list to merge
    // In Solidity, we process from right to left, so reverse the direct bases
    let mut direct_bases_reversed = direct_bases.to_vec();
    direct_bases_reversed.reverse();
    parent_linearizations.push(direct_bases_reversed);

    // Perform C3 merge
    let mut merged = c3_merge(parent_linearizations, contract_name)?;

    // Reverse to get most base to most derived order (Solidity convention)
    // This ensures proper Method Resolution Order for future features
    merged.reverse();

    Ok(merged)
}

/// The C3 merge operation
///
/// Merges multiple linearization lists according to the C3 algorithm rules:
/// 1. Find the first head that doesn't appear in any tail
/// 2. Add it to the result
/// 3. Remove it from all heads
/// 4. Repeat until all lists are empty
fn c3_merge(mut lists: Vec<Vec<String>>, contract_name: &str) -> Result<Vec<String>, String> {
    let mut result = Vec::new();

    // Remove empty lists
    lists.retain(|list| !list.is_empty());

    while !lists.is_empty() {
        // Find a good head (one that doesn't appear in any tail)
        let mut good_head: Option<String> = None;

        for list in &lists {
            if list.is_empty() {
                continue;
            }

            let candidate = &list[0];
            let mut is_good = true;

            // Check if this candidate appears in the tail of any list
            for other_list in &lists {
                if other_list.len() > 1 && other_list[1..].contains(candidate) {
                    is_good = false;
                    break;
                }
            }

            if is_good {
                good_head = Some(candidate.clone());
                break;
            }
        }

        match good_head {
            Some(head) => {
                // Add the good head to result
                result.push(head.clone());

                // Remove the head from all lists where it appears as the first element
                for list in &mut lists {
                    if !list.is_empty() && list[0] == head {
                        list.remove(0);
                    }
                }

                // Remove empty lists
                lists.retain(|list| !list.is_empty());
            }
            None => {
                // No good head found - inconsistent hierarchy
                return Err(format!(
                    "Cannot create a consistent linearization for '{}'. \
                    Inconsistent hierarchy detected. Remaining lists: {:?}",
                    contract_name, lists
                ));
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_simple_inheritance() {
        // A <- B
        let mut linearizations = HashMap::new();
        linearizations.insert("A".to_string(), vec![]);

        let get_lin = |name: &str| -> Result<Vec<String>, String> {
            linearizations
                .get(name)
                .cloned()
                .ok_or_else(|| format!("Contract {} not found", name))
        };

        let result = c3_linearize("B", &["A".to_string()], get_lin).unwrap();
        assert_eq!(result, vec!["A"]);
    }

    #[test]
    fn test_multiple_inheritance() {
        // A, B <- C
        let mut linearizations = HashMap::new();
        linearizations.insert("A".to_string(), vec![]);
        linearizations.insert("B".to_string(), vec![]);

        let get_lin = |name: &str| -> Result<Vec<String>, String> {
            linearizations
                .get(name)
                .cloned()
                .ok_or_else(|| format!("Contract {} not found", name))
        };

        // In Solidity: contract C is A, B
        // Direct bases are in order: most base-like (A) to most derived (B)
        let result = c3_linearize("C", &["A".to_string(), "B".to_string()], get_lin).unwrap();
        // Result should be [A, B] (base to derived)
        assert_eq!(result, vec!["A", "B"]);
    }

    #[test]
    fn test_diamond_inheritance() {
        // Classic diamond:
        //     A
        //    / \
        //   B   C
        //    \ /
        //     D

        let mut linearizations = HashMap::new();
        linearizations.insert("A".to_string(), vec![]);
        linearizations.insert("B".to_string(), vec!["A".to_string()]);
        linearizations.insert("C".to_string(), vec!["A".to_string()]);

        let get_lin = |name: &str| -> Result<Vec<String>, String> {
            linearizations
                .get(name)
                .cloned()
                .ok_or_else(|| format!("Contract {} not found", name))
        };

        // In Solidity: contract D is B, C
        let result = c3_linearize("D", &["B".to_string(), "C".to_string()], get_lin).unwrap();
        // Result should be [A, B, C] following C3 rules
        assert_eq!(result, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_complex_inheritance() {
        // More complex example:
        // A <- B <- D
        // A <- C <- D

        let mut linearizations = HashMap::new();
        linearizations.insert("A".to_string(), vec![]);
        linearizations.insert("B".to_string(), vec!["A".to_string()]);
        linearizations.insert("C".to_string(), vec!["A".to_string()]);

        let get_lin = |name: &str| -> Result<Vec<String>, String> {
            linearizations
                .get(name)
                .cloned()
                .ok_or_else(|| format!("Contract {} not found", name))
        };

        // contract D is B, C
        let result = c3_linearize("D", &["B".to_string(), "C".to_string()], get_lin).unwrap();
        assert_eq!(result, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_inconsistent_hierarchy() {
        // This should fail - inconsistent hierarchy
        // Trying to create a situation where C3 cannot find a consistent linearization

        let mut linearizations = HashMap::new();
        // Set up a problematic hierarchy
        linearizations.insert("A".to_string(), vec![]);
        linearizations.insert("B".to_string(), vec![]);
        linearizations.insert("C".to_string(), vec!["A".to_string(), "B".to_string()]);
        linearizations.insert("D".to_string(), vec!["B".to_string(), "A".to_string()]);

        let get_lin = |name: &str| -> Result<Vec<String>, String> {
            linearizations
                .get(name)
                .cloned()
                .ok_or_else(|| format!("Contract {} not found", name))
        };

        // Try to inherit from both C and D with conflicting orders
        let result = c3_linearize("E", &["C".to_string(), "D".to_string()], get_lin);
        assert!(result.is_err());
    }
}
