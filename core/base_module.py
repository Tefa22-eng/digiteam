# core/base_module.py
"""
Base module class that all recon modules inherit from.
Provides standardized interface, error handling, and result collection.
"""

import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from utils.logger import setup_logger


class ModuleStatus(Enum):
    """Module execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ModuleResult:
    """Standardized result container for all modules."""
    module_name: str
    status: ModuleStatus = ModuleStatus.PENDING
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "module_name": self.module_name,
            "status": self.status.value,
            "data": self.data,
            "errors": self.errors,
            "warnings": self.warnings,
            "execution_time": round(self.execution_time, 2),
            "timestamp": self.timestamp,
        }


class BaseModule(ABC):
    """
    Abstract base class for all reconnaissance modules.
    Enforces a consistent interface and provides common functionality.
    """

    def __init__(self, target: str, config, module_name: str = ""):
        self.target = target
        self.config = config
        self.module_name = module_name or self.__class__.__name__
        self.logger = setup_logger(f"digiteam.module.{self.module_name}")
        self.result = ModuleResult(module_name=self.module_name)

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of what the module does."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Module category: 'passive' or 'active'."""
        pass

    @abstractmethod
    def _run(self) -> Dict[str, Any]:
        """
        Core module logic. Must be implemented by subclasses.
        Returns a dict of collected data.
        """
        pass

    def pre_check(self) -> bool:
        """
        Pre-execution check. Override in subclass to verify
        dependencies, API keys, tool availability, etc.
        Returns True if the module can run.
        """
        return True

    def execute(self) -> ModuleResult:
        """
        Execute the module with full lifecycle management.
        Handles timing, error handling, and status tracking.
        """
        self.result.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if not self.pre_check():
            self.result.status = ModuleStatus.SKIPPED
            self.result.warnings.append("Pre-check failed; module skipped")
            self.logger.warning(f"{self.module_name} skipped (pre-check failed)")
            return self.result

        self.result.status = ModuleStatus.RUNNING
        start_time = time.time()

        try:
            data = self._run()
            self.result.data = data if data else {}
            self.result.status = ModuleStatus.COMPLETED
            self.logger.info(f"{self.module_name} completed successfully")
        except Exception as e:
            self.result.status = ModuleStatus.FAILED
            self.result.errors.append(str(e))
            self.logger.error(
                f"{self.module_name} failed: {e}\n{traceback.format_exc()}"
            )
        finally:
            self.result.execution_time = time.time() - start_time

        return self.result