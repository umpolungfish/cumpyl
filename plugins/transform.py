"""Transform module for Go Binary Analysis Plugin"""
import shutil
import logging
import os
import time
import json
from typing import Any, Dict, List, Tuple, Optional, Union
from plugins.crypto_utils import safe_hash
from jsonschema import validate, ValidationError

logger = logging.getLogger(__name__)

# Schema for transformation plan validation
TRANSFORMATION_SCHEMA = {
    "type": "object",
    "properties": {
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["go_binary_detected", "packing_opportunity"]},
                    "description": {"type": "string"},
                    "timestamp": {"type": "integer"},
                    "section": {"type": "string"},
                    "size": {"type": "integer"},
                    "entropy": {"type": "number"},
                    "confidence": {"type": "number"},
                    "recommendation": {"type": "string"}
                },
                "required": ["type", "timestamp"]
            }
        },
        "metadata": {
            "type": "object",
            "properties": {
                "plugin_name": {"type": "string"},
                "analysis_based": {"type": "boolean"},
                "actual_transformation": {"type": "boolean"},
                "timestamp": {"type": "integer"},
                "binary_format": {"type": "string"},
                "sections_count": {"type": "integer"},
                "packing_opportunities_count": {"type": "integer"}
            },
            "required": ["plugin_name", "timestamp"]
        }
    },
    "required": ["actions", "metadata"]
}

class TransformationPlan:
    """Enhanced class to hold transformation plan information with metadata integrity"""
    def __init__(self) -> None:
        self.actions: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}

def create_transformation_plan(binary: Any, analysis_results: Dict[str, Any]) -> TransformationPlan:
    """
    Create a comprehensive transformation plan based on analysis results
    
    Args:
        binary: Binary object to transform
        analysis_results: Results from binary analysis
        
    Returns:
        TransformationPlan: Plan with actions and metadata
    """
    logger.debug(f"Creating transformation plan for binary: {getattr(binary, 'path', 'unknown')}")
    plan = TransformationPlan()
    
    # Extract relevant information from analysis results
    go_detected: bool = analysis_results.get("analysis", {}).get("go_detection", {}).get("detected", False)
    packing_opportunities: List[Dict[str, Any]] = analysis_results.get("analysis", {}).get("packing_opportunities", [])
    
    logger.info(f"Go binary detected: {go_detected}, Packing opportunities: {len(packing_opportunities)}")
    
    # Create detailed actions based on analysis
    if go_detected:
        action: Dict[str, Any] = {
            "type": "go_binary_detected",
            "description": "Go binary detected, transformation planning initiated",
            "timestamp": int(time.time())
        }
        plan.actions.append(action)
        logger.debug("Added go_binary_detected action to plan")
    
    # Add actions for packing opportunities
    for opportunity in packing_opportunities:
        action = {
            "type": "packing_opportunity",
            "section": opportunity.get("section"),
            "size": opportunity.get("size"),
            "entropy": opportunity.get("entropy"),
            "confidence": opportunity.get("confidence"),
            "recommendation": opportunity.get("recommendation"),
            "description": f"Potential packing opportunity in section {opportunity.get('section')}",
            "timestamp": int(time.time())
        }
        plan.actions.append(action)
        logger.debug(f"Added packing opportunity for section {opportunity.get('section')} (size: {opportunity.get('size')})")
    
    # Add comprehensive metadata
    plan.metadata = {
        "plugin_name": "go_binary_analyzer",
        "analysis_based": True,
        "actual_transformation": False,
        "timestamp": int(time.time()),
        "binary_format": analysis_results.get("binary_format", "UNKNOWN"),
        "sections_count": analysis_results.get("analysis", {}).get("sections_count", 0),
        "packing_opportunities_count": len(packing_opportunities)
    }
    logger.debug(f"Plan metadata: {plan.metadata}")
    
    return plan

def validate_transformation_plan_schema(plan: Union[TransformationPlan, Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Validate transformation plan against JSON schema.
    
    Args:
        plan: Transformation plan to validate
        
    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)
    """
    try:
        plan_dict = {
            "actions": plan.actions,
            "metadata": plan.metadata
        } if hasattr(plan, 'actions') and hasattr(plan, 'metadata') else plan
        validate(instance=plan_dict, schema=TRANSFORMATION_SCHEMA)
        return True, None
    except ValidationError as e:
        return False, f"Schema validation failed: {str(e)}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def validate_transformation_plan(plan: Union[TransformationPlan, Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Validate the transformation plan for consistency and feasibility.
    
    Args:
        plan: Transformation plan to validate
        
    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)
    """
    # Use schema validation
    return validate_transformation_plan_schema(plan)

def validate_binary_object(binary: Any) -> bool:
    """
    Validate the binary object structure
    
    Args:
        binary: Binary object to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not binary:
        logger.error("No binary provided")
        return False
    
    if not hasattr(binary, 'path') or not binary.path:
        logger.error("Binary object lacks valid 'path' attribute")
        return False
    
    if not hasattr(binary, 'sections'):
        logger.error("Binary object lacks 'sections' attribute")
        return False
    
    return True

def generate_dry_run_report(binary: Any, plan: Union[TransformationPlan, Dict[str, Any]], output_path: str = "dry_run_report.json") -> Dict[str, Any]:
    """
    Generate a detailed report of planned transformations during dry-run mode
    
    Args:
        binary: Binary object
        plan: Transformation plan
        output_path: Path to save the report
        
    Returns:
        Dict[str, Any]: Dry run report
    """
    # Convert plan to dict if it's an object
    if hasattr(plan, 'actions') and hasattr(plan, 'metadata'):
        plan_actions = plan.actions
        plan_metadata = plan.metadata
    else:
        plan_actions = plan.get("actions", [])
        plan_metadata = plan.get("metadata", {})
    
    dry_run_report = {
        "timestamp": int(time.time()),
        "binary_path": getattr(binary, 'path', 'unknown'),
        "binary_format": plan_metadata.get('binary_format', 'UNKNOWN'),
        "actions": plan_actions,
        "metadata": plan_metadata,
        "status": "dry_run",
        "summary": {
            "total_actions": len(plan_actions),
            "go_binary_detected": any(action["type"] == "go_binary_detected" for action in plan_actions),
            "packing_opportunities": len([action for action in plan_actions if action["type"] == "packing_opportunity"])
        }
    }
    
    try:
        with open(output_path, 'w') as f:
            json.dump(dry_run_report, f, indent=2)
        logger.info(f"Dry-run report saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save dry-run report: {e}")
    
    return dry_run_report

def apply_transformation_plan(binary: Any, plan: Union[TransformationPlan, Dict[str, Any]], allow_transform: bool = False, dry_run_output: str = "dry_run_report.json") -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Apply transformation with comprehensive safeguards and reporting.
    
    Args:
        binary: Binary object to transform
        plan: Transformation plan
        allow_transform: Whether to actually apply transformations
        dry_run_output: Path for dry-run report
        
    Returns:
        Tuple[bool, Optional[Dict[str, Any]]]: (success, report_or_none)
    """
    # Validate plan before proceeding
    is_valid, error = validate_transformation_plan(plan)
    if not is_valid:
        logger.error(f"Transformation plan validation failed: {error}")
        return False, {
            "status": "error",
            "error_code": "INVALID_PLAN",
            "message": f"Transformation plan is invalid: {error}",
            "suggestion": "Check the plan structure against TRANSFORMATION_SCHEMA and ensure all required fields are present."
        }
    
    # Validate binary object
    if not validate_binary_object(binary):
        return False, {
            "status": "error",
            "error_code": "INVALID_BINARY",
            "message": "Binary object is invalid or missing required attributes.",
            "suggestion": "Ensure the binary object is properly initialized and contains valid sections."
        }

    # Enforce dry-run unless explicitly authorized via environment variable
    transform_authorized = os.environ.get('CUMPYL_TRANSFORM_AUTH', 'false').lower() == 'true'
    if allow_transform and not transform_authorized:
        logger.warning("Transformation requested but not authorized via CUMPYL_TRANSFORM_AUTH; falling back to dry-run")
        allow_transform = False

    # Dry-run mode: Generate detailed report
    if not allow_transform:
        logger.info("Transformation disabled by config or authorization - running in dry-run mode")
        dry_run_report = generate_dry_run_report(binary, plan, dry_run_output)
        return True, dry_run_report

    # Pre-flight: Backup original with timestamped filename
    backup_path = f"backup_{os.path.basename(binary.path)}_{int(time.time())}.bin"
    try:
        shutil.copy(binary.path, backup_path)
        logger.info(f"Backup created at {backup_path}")
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        return False, {
            "status": "error",
            "error_code": "BACKUP_FAILED",
            "message": f"Failed to create backup: {str(e)}",
            "suggestion": "Check file permissions and available disk space."
        }

    # Apply transformations with rollback on failure
    try:
        # Convert plan to dict if it's an object
        if hasattr(plan, 'actions') and hasattr(plan, 'metadata'):
            plan_actions = plan.actions
        else:
            plan_actions = plan.get("actions", [])
        
        logger.info(f"Applying {len(plan_actions)} transformation actions")
        for i, action in enumerate(plan_actions):
            logger.info(f"Executing action {i+1}/{len(plan_actions)}: {action['type']} - {action.get('description', '')}")
            
            # Simulate transformation based on action type
            if action["type"] == "go_binary_detected":
                logger.debug("Processing Go binary detection action")
                # In a real implementation, add Go-specific transformation logic here
                pass
            elif action["type"] == "packing_opportunity":
                logger.debug(f"Processing packing opportunity for section {action.get('section')}")
                # In a real implementation, add packing logic here
                pass
            else:
                logger.warning(f"Unknown action type: {action['type']}")
        
        logger.info("All transformation actions completed successfully")
        return True, None
        
    except Exception as e:
        logger.error(f"Transformation failed: {e}")
        # Attempt rollback
        try:
            shutil.copy(backup_path, binary.path)
            logger.info(f"Restored original binary from {backup_path}")
        except Exception as restore_e:
            logger.error(f"Rollback failed: {restore_e}")
        return False, {
            "status": "error",
            "error_code": "TRANSFORMATION_FAILED",
            "message": f"Transformation failed: {str(e)}",
            "suggestion": "Check the error log for details. The original binary should be restored from backup."
        }

def get_transformation_summary(plan: Union[TransformationPlan, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a summary of the transformation plan
    
    Args:
        plan: Transformation plan
        
    Returns:
        Dict[str, Any]: Summary of the plan
    """
    # Convert plan to dict if it's an object
    if hasattr(plan, 'actions') and hasattr(plan, 'metadata'):
        plan_actions = plan.actions
        plan_metadata = plan.metadata
    else:
        plan_actions = plan.get("actions", [])
        plan_metadata = plan.get("metadata", {})
    
    summary = {
        "total_actions": len(plan_actions),
        "action_types": {},
        "metadata": plan_metadata
    }
    
    # Count action types
    for action in plan_actions:
        action_type = action.get("type", "unknown")
        summary["action_types"][action_type] = summary["action_types"].get(action_type, 0) + 1
    
    return summary