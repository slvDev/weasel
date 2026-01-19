use crate::config::Config;
use crate::core::context::AnalysisContext;
use crate::core::processor::{AnalysisResults, Processor};
use crate::core::project_detector::{ProjectConfig, ProjectType};
use crate::core::registry::DetectorRegistry;
use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::{Finding, Report};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AnalysisEngine {
    context: AnalysisContext,
    registry: DetectorRegistry,
    visitor: ASTVisitor,
    processor: Processor,
    config: Config,
}

impl AnalysisEngine {
    pub fn new(config: &Config) -> Self {
        Self {
            context: AnalysisContext::new(),
            registry: DetectorRegistry::new(),
            visitor: ASTVisitor::new(),
            processor: Processor::new(),
            config: config.clone(),
        }
    }

    pub fn register_detector(&mut self, detector: Arc<dyn Detector>) {
        if detector.severity().as_value() >= self.config.min_severity.as_value() {
            self.registry.register(detector);
        }
    }

    pub fn register_built_in_detectors(&mut self) {
        // High severity detectors
        self.register_detector(Arc::new(
            crate::detectors::high::ComparisonWithoutEffectDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::high::DelegatecallInLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::high::CurveSpotPriceOracleDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::high::MsgValueInLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::high::WstethStethPerTokenUsageDetector::default(),
        ));

        // Medium severity detectors
        self.register_detector(Arc::new(
            crate::detectors::medium::BlockNumberL2Detector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::CentralizationRiskDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::ChainlinkStalePriceDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::DeprecatedChainlinkFunctionDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::DeprecatedTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::DirectSupportsInterfaceDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::Eip712ComplianceDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::FeeOnTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::L2SequencerCheckDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::LibraryFunctionVisibilityDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::NftMintAsymmetryDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::SoladySafeTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::SolmateSafeTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::TxOriginUsageDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnboundedFeeDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UncheckedLowLevelCallDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UncheckedTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnsafeApproveDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnsafeErc20OperationsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnsafeMintDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnsafeTransferFromDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UsdtAllowanceDetector::default(),
        ));

        // Low severity detectors
        self.register_detector(Arc::new(
            crate::detectors::low::AssemblyOptimizerBugDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::BlockTimestampDeadlineDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::ConstantDecimalsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::CurveCalcTokenAmountDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DecimalsTypeDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DeprecatedAbiEncoderV2Detector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DeprecatedApproveDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DeprecatedSafeApproveDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DeprecatedSetupRoleDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DivisionBeforeMultiplicationDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DivisionByZeroDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DivisionRoundingDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DomainSeparatorReplayDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::DuplicateImportDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::EcrecoverMalleabilityDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::EmptyFunctionBodyDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::EmptyEtherReceiverDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::Erc20DecimalsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::Erc20SymbolNotStandardDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::ExternalCallInLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::FallbackLackingPayableDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::InitializerFrontrunDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::InitializerOnInternalDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::LackOfSlippageCheckDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::LargeApprovalDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::LowLevelCallGasGriefDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::MintBurnAddressValidationDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::MissingGapStorageDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::MissingZeroAddressValidationDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::NftHardForkDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::Push0OpcodeDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::RenounceWhilePausedDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::SweepTokenAccountingDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::TwoStepOwnershipTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UnlimitedGasCallDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UnspecificPragmaDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UnsafeAbiEncodePackedDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UnsafeDowncastDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UnsafeIntCastDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UnsafeIntToUintCastDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UninitializedImplementationDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UninitializedUpgradeableDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UnsafeLowLevelCallDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::UpgradableTokenInterfaceDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::Year365DaysDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::low::ZeroValueTransferDetector::default(),
        ));

        // Gas detectors
        self.register_detector(Arc::new(
            crate::detectors::gas::AddressThisPrecalculationDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::AssemblyAbiDecodeDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::AddressZeroCheckDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::AssemblyStorageWriteDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::ArrayCompoundAssignmentDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::ArrayLengthInLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::BooleanComparisonDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CompoundAssignmentDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::MsgSenderUsageDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::UnsafeArrayAccessDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::VariableInsideLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::BoolStorageDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CachedConstantDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CachedImmutableDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CachedMsgSenderDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CalldataInsteadOfMemoryDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CombineMappingsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CountDownLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::UncheckedLoopIncrementDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CustomErrorsInsteadOfRevertStringsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CacheStateVariablesDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::AvoidContractExistenceChecksDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::UnnecessaryVariableCacheDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::UseErc721aDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::DefaultValueInitializationDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::InternalFunctionNotCalledDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::LongRevertStringDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::PayableFunctionDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::PostIncrementDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::PrivateConstantsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::ShiftInsteadOfMulDivDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::SplitRequireDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::SuperfluousEventFieldsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::ShouldBeImmutableDetector::default(),
        ));
        self.register_detector(Arc::new(crate::detectors::gas::ThisUsageDetector::default()));
        self.register_detector(Arc::new(
            crate::detectors::gas::UintGtZeroDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::Uint256ToBoolMappingDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::WethAddressDefinitionDetector::default(),
        ));

        // NC detectors
        self.register_detector(Arc::new(
            crate::detectors::nc::AbstractInSeparateFileDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ArrayIndicesDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ArrayRangedGetterDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::BoolInitFalseDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::AbiEncodeCallDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::UnnecessaryAbiCoderV2Detector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ConstantCaseDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ConstantExpressionDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ConstructorEmitEventDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::InitializerEmitEventDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::InitialismCapitalizationDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ControlStructureStyleDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ContractLayoutDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::CustomErrorNoArgsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MagicNumberDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ManyFunctionParamsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ManyReturnValuesDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MappingStyleDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MissingErrorMessageDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MissingEventSetterDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MissingSpdxDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MixedIntUintStyleDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MultipleAbstractContractsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MultipleContractsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MultipleInterfacesDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MultipleLibrariesDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::NamedFunctionArgsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::NamedMappingsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::NamedReturnsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::NonReentrantBeforeModifiersDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::NumericUnderscoresDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::TwoStepCriticalChangesDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::TypeMaxLiteralDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::TypeMaxValueDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::UppercaseNonConstantDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::UnderscorePrefixDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::UnnamedRevertDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::UnusedOverrideParamsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::UnusedPrivateFunctionDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::WhileTrueLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ZeroInitializationDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::PreferRequireDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::PublicToExternalDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::PreferConcatDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::PreferCustomErrorsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::PreferModifierDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::DefaultVisibilityDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::DeleteInsteadOfFalseDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::DeleteInsteadOfZeroDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::DeprecatedSafeMathDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ConsoleLogImportDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::RenounceOwnershipDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ScientificNotationDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::SensitiveTermsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::SetterEventOldValueDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::SetterNoCheckDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::StringQuotesDetector::default(),
        ));
        self.register_detector(Arc::new(crate::detectors::nc::TimeUnitsDetector::default()));
        self.register_detector(Arc::new(crate::detectors::nc::TodoLeftDetector::default()));
        self.register_detector(Arc::new(
            crate::detectors::nc::DraftDependencyDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::DuplicateRequireDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::DuplicateStringLiteralDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::EcrecoverVCheckDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::EmptyBlocksDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ErrorDefinitionNoArgsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::RedundantElseDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::RedundantReturnDetector::default(),
        ));
        self.register_detector(Arc::new(crate::detectors::nc::EventArgsDetector::default()));
        self.register_detector(Arc::new(
            crate::detectors::nc::EventMissingIndexedArgsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ExternalCallInModifierDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::FloatingPragmaDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::FunctionLengthDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::FunctionOrderDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::HardcodedAddressDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::InterfaceInSeparateFileDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::InterfaceNamingDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::InterfacesContractsSameFileDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::LargeLiteralDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::LibraryInSeparateFileDetector::default(),
        ));
        self.register_detector(Arc::new(crate::detectors::nc::LineLengthDetector::default()));
        self.register_detector(Arc::new(
            crate::detectors::nc::LongCalculationsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ExplicitNumTypesDetector::default(),
        ));
    }

    pub fn analyze(&mut self) -> Result<Report, String> {
        // Determine project root - look for project markers
        let project_root = self
            .config
            .scope
            .first()
            .and_then(|p| {
                // Start from the scope path and walk up to find project root
                let mut current = if p.is_dir() {
                    p.clone()
                } else {
                    p.parent().map(|parent| parent.to_path_buf())?
                };

                // Walk up directories looking for project markers
                loop {
                    // Check for project configuration files
                    if current.join("foundry.toml").exists()
                        || current.join("hardhat.config.js").exists()
                        || current.join("hardhat.config.ts").exists()
                        || current.join("truffle-config.js").exists()
                    {
                        return Some(current);
                    }

                    // Move up one directory
                    match current.parent() {
                        Some(parent) if parent != current => {
                            current = parent.to_path_buf();
                        }
                        _ => break,
                    }
                }

                // If no project marker found, use the original logic
                if p.is_dir() {
                    Some(p.clone())
                } else {
                    p.parent().map(|parent| parent.to_path_buf())
                }
            })
            .unwrap_or_else(|| PathBuf::from("."));

        // Auto-detect project configuration
        let project_config = ProjectConfig::auto_detect(&project_root).unwrap_or_else(|e| {
            eprintln!("Note: Could not auto-detect project type: {}", e);
            // Fallback to custom config
            ProjectConfig::from_manual_config(
                project_root.clone(),
                HashMap::new(),
                vec![PathBuf::from("lib"), PathBuf::from("node_modules")],
                vec![PathBuf::from("src")],
            )
        });

        // Use project's default scope if user didn't specify one
        let scope = if self.config.scope.is_empty() {
            &project_config.default_scope
        } else {
            &self.config.scope
        };

        // Build remappings with proper precedence
        let final_remappings = if project_config.project_type == ProjectType::Foundry {
            // Convert CLI remappings to HashMap
            let cli_remappings: HashMap<String, String> = self
                .config
                .remappings
                .iter()
                .filter_map(|r| {
                    r.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                })
                .collect();

            // Use full precedence: defaults -> remappings.txt -> foundry.toml -> CLI
            ProjectConfig::load_remappings_with_precedence(
                &project_config.project_root,
                &cli_remappings,
            )
            .unwrap_or_else(|e| {
                eprintln!("Warning: Failed to load remappings: {}", e);
                project_config.remappings.clone()
            })
        } else {
            // For non-Foundry projects, use auto-detected + CLI override
            let mut remappings = project_config.remappings.clone();
            for r in &self.config.remappings {
                if let Some((from, to)) = r.split_once('=') {
                    remappings.insert(from.to_string(), PathBuf::from(to));
                }
            }
            remappings
        };

        self.context
            .set_import_resolver(final_remappings, project_config.project_root.clone());

        // Set library paths in the import resolver
        if let Some(ref mut resolver) = self.context.get_import_resolver_mut() {
            resolver.add_library_paths(project_config.library_paths.clone());
        }

        self.context.load_files(&scope, &self.config.exclude)?;

        self.context.build_cache()?;

        if !self.context.missing_contracts.is_empty() {
            eprintln!(
                "Warning: {} missing contracts detected:",
                self.context.missing_contracts.len()
            );
            for missing in &self.context.missing_contracts {
                eprintln!("  - {}", missing);
            }
        }

        let detectors = self.registry.get_all();
        for detector_arc in detectors.clone() {
            detector_arc.register_callbacks(&mut self.visitor);
        }

        let results =
            self.processor
                .process_files(&self.context.files, &self.visitor, &self.context);

        let report = self.generate_report_from_results(&results);

        Ok(report)
    }

    fn generate_report_from_results(&self, results: &AnalysisResults) -> Report {
        let mut report = Report::new();

        for (detector_id, locations) in &results.findings_by_detector {
            if let Some(detector) = self.registry.get(detector_id) {
                let finding = Finding {
                    detector_id: detector_id.to_string(),
                    severity: detector.severity(),
                    title: detector.name().to_string(),
                    description: detector.description().to_string(),
                    example: detector.example(),
                    locations: locations.clone(),
                };
                report.add_finding(finding);
            }
        }

        // Sort findings by severity (High -> Medium -> Low -> Gas -> NC)
        report
            .findings
            .sort_by(|a, b| b.severity.as_value().cmp(&a.severity.as_value()));

        // Add metadata
        report.add_metadata("Version:", crate::core::version());
        report.add_metadata(
            "Timestamp:",
            &chrono::Utc::now().format("%d/%m/%Y %H:%M:%S").to_string(),
        );
        report.add_metadata("Total Findings:", &results.total_findings().to_string());

        report
    }

    // Getters
    pub fn registry(&self) -> &DetectorRegistry {
        &self.registry
    }

    pub fn get_detector_info(&self) -> Vec<DetectorInfo> {
        self.registry
            .get_all()
            .iter()
            .map(|d| DetectorInfo {
                id: d.id().to_string(),
                name: d.name().to_string(),
                severity: format!("{:?}", d.severity()),
                description: d.description().to_string(),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct DetectorInfo {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub description: String,
}
