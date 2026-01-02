use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DivisionRoundingDetector;

impl Detector for DivisionRoundingDetector {
    fn id(&self) -> &'static str {
        "division-rounding"
    }

    fn name(&self) -> &str {
        "Division by large number may round to zero"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Division by large numbers (reserves, balances, supplies, totals, liquidity, stakes, \
         deposits, collateral, assets, TVL, debt, pool amounts) may result in the result being \
         zero, due to Solidity not supporting fractions. Consider requiring a minimum amount for \
         the numerator or multiplying before dividing to maintain precision."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - division by large number may round to zero
uint256 share = amount / totalSupply;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            find_in_statement(body, file, self.id(), |expr| {
                if let Expression::Divide(_, _, right) = expr {
                    Self::contains_large_number_variable(right.as_ref())
                } else {
                    false
                }
            })
        });
    }
}

impl DivisionRoundingDetector {
    fn contains_large_number_variable(expr: &Expression) -> bool {
        match expr {
            Expression::Variable(id) => Self::is_large_number_name(&id.name),
            Expression::MemberAccess(_, base, member) => {
                if Self::is_large_number_name(&member.name) {
                    return true;
                }
                Self::contains_large_number_variable(base.as_ref())
            }
            Expression::FunctionCall(_, func, args) => {
                if Self::contains_large_number_variable(func.as_ref()) {
                    return true;
                }
                args.iter()
                    .any(|arg| Self::contains_large_number_variable(arg))
            }
            Expression::Parenthesis(_, inner) => {
                Self::contains_large_number_variable(inner.as_ref())
            }
            Expression::Add(_, left, right)
            | Expression::Subtract(_, left, right)
            | Expression::Multiply(_, left, right)
            | Expression::Divide(_, left, right) => {
                Self::contains_large_number_variable(left.as_ref())
                    || Self::contains_large_number_variable(right.as_ref())
            }
            _ => false,
        }
    }

    fn is_large_number_name(name: &str) -> bool {
        let name_lower = name.to_lowercase();

        const LARGE_NUMBER_KEYWORDS: &[&str] = &[
            "reserve",    // AMM reserves
            "balance",    // Token balances
            "supply",     // Total supply
            "total",      // Total amounts
            "liquidity",  // Pool liquidity
            "stake",      // Staked amounts (also matches "staked")
            "deposit",    // Deposited amounts (also matches "deposited")
            "collateral", // Collateral in lending
            "assets",     // Vault assets
            "tvl",        // Total Value Locked
            "locked",     // Locked amounts
            "debt",       // Debt amounts
            "pool",       // Pool amounts
        ];

        LARGE_NUMBER_KEYWORDS
            .iter()
            .any(|keyword| name_lower.contains(keyword))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_division_by_large_numbers() {
        let code = r#"
            interface IPool {
                function totalSupply() external view returns (uint256);
                function balanceOf(address) external view returns (uint256);
            }

            contract Test {
                uint256 public totalSupply;
                uint256 public reserve0;
                uint256 public liquidity;
                uint256 public totalStaked;
                uint256 public totalDeposited;
                uint256 public collateralAmount;
                uint256 public totalAssets;
                uint256 public tvl;
                uint256 public lockedAmount;
                uint256 public totalDebt;
                uint256 public poolBalance;
                IPool public pool;

                function bad1(uint256 amount) public view returns (uint256) {
                    return amount / totalSupply;
                }

                function bad2(uint256 amount) public view returns (uint256) {
                    return amount / reserve0;
                }

                function bad3(uint256 amount) public view returns (uint256) {
                    return amount / liquidity;
                }

                function bad4(uint256 amount) public view returns (uint256) {
                    return amount / totalStaked;
                }

                function bad5(uint256 amount) public view returns (uint256) {
                    return amount / totalDeposited;
                }

                function bad6(uint256 amount) public view returns (uint256) {
                    return amount / collateralAmount;
                }

                function bad7(uint256 amount) public view returns (uint256) {
                    return amount / totalAssets;
                }

                function bad8(uint256 amount) public view returns (uint256) {
                    return amount / tvl;
                }

                function bad9(uint256 amount) public view returns (uint256) {
                    return amount / lockedAmount;
                }

                function bad10(uint256 amount) public view returns (uint256) {
                    return amount / totalDebt;
                }

                function bad11(uint256 amount) public view returns (uint256) {
                    return amount / poolBalance;
                }

                function bad12(uint256 amount) public view returns (uint256) {
                    return amount / pool.totalSupply();
                }
            }
        "#;
        let detector = Arc::new(DivisionRoundingDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 12);
        assert_eq!(locations[0].line, 22, "amount / totalSupply");
        assert_eq!(locations[1].line, 26, "amount / reserve0");
        assert_eq!(locations[2].line, 30, "amount / liquidity");
        assert_eq!(locations[3].line, 34, "amount / totalStaked");
        assert_eq!(locations[4].line, 38, "amount / totalDeposited");
        assert_eq!(locations[5].line, 42, "amount / collateralAmount");
        assert_eq!(locations[6].line, 46, "amount / totalAssets");
        assert_eq!(locations[7].line, 50, "amount / tvl");
        assert_eq!(locations[8].line, 54, "amount / lockedAmount");
        assert_eq!(locations[9].line, 58, "amount / totalDebt");
        assert_eq!(locations[10].line, 62, "amount / poolBalance");
        assert_eq!(locations[11].line, 66, "amount / pool.totalSupply()");
    }

    #[test]
    fn test_skips_safe_divisions() {
        let code = r#"
            contract Test {
                uint256 public constant PRECISION = 1e18;
                uint256 public price;
                uint256 public rate;

                function safe1(uint256 amount) public pure returns (uint256) {
                    return amount / 100;
                }

                function safe2(uint256 amount, uint256 divisor) public pure returns (uint256) {
                    return amount / divisor;
                }

                function safe3(uint256 amount) public view returns (uint256) {
                    return amount / price;
                }

                function safe4(uint256 amount) public pure returns (uint256) {
                    return amount / PRECISION;
                }

                function safe5(uint256 amount, uint256 count) public pure returns (uint256) {
                    return amount / count;
                }

                function safe6(uint256 amount) public view returns (uint256) {
                    return amount / rate;
                }

                function safe7(uint256 amount, uint256 shares) public pure returns (uint256) {
                    return amount / shares;
                }

                function safe8(uint256 amount, uint256 index) public pure returns (uint256) {
                    return amount / index;
                }
            }
        "#;
        let detector = Arc::new(DivisionRoundingDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
