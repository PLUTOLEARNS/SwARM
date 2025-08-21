"""Base agent class for all SwARM agents"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from src.utils.logger import get_logger
from src.utils.metrics import metrics


class BaseAgent(ABC):
    """Abstract base class for all SwARM agents"""
    
    def __init__(self, agent_id: str, config: Dict[str, Any]):
        """Initialize base agent
        
        Args:
            agent_id: Unique identifier for the agent
            config: Agent configuration
        """
        self.agent_id = agent_id
        self.config = config
        self.logger = get_logger(f'agent.{agent_id}')
        self.running = False
        self.tasks = []
        
        self.logger.info(f"Agent {agent_id} initialized")
    
    async def start(self):
        """Start the agent"""
        self.logger.info(f"Starting agent {self.agent_id}")
        self.running = True
        
        try:
            await self._on_start()
            metrics.increment('agents_started')
            self.logger.info(f"Agent {self.agent_id} started successfully")
        except Exception as e:
            self.logger.error(f"Error starting agent {self.agent_id}: {e}")
            self.running = False
            raise
    
    async def stop(self):
        """Stop the agent"""
        self.logger.info(f"Stopping agent {self.agent_id}")
        self.running = False
        
        try:
            # Cancel all tasks
            for task in self.tasks:
                task.cancel()
            
            # Wait for tasks to complete
            if self.tasks:
                await asyncio.gather(*self.tasks, return_exceptions=True)
            
            await self._on_stop()
            metrics.increment('agents_stopped')
            self.logger.info(f"Agent {self.agent_id} stopped")
        except Exception as e:
            self.logger.error(f"Error stopping agent {self.agent_id}: {e}")
    
    def is_alive(self) -> bool:
        """Check if agent is alive and running
        
        Returns:
            True if agent is running
        """
        return self.running
    
    @abstractmethod
    async def _on_start(self):
        """Called when agent starts - implement in subclasses"""
        pass
    
    @abstractmethod
    async def _on_stop(self):
        """Called when agent stops - implement in subclasses"""
        pass
    
    @abstractmethod
    async def get_report(self) -> Optional[Dict[str, Any]]:
        """Get agent status report - implement in subclasses
        
        Returns:
            Agent report dictionary or None
        """
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get basic agent status
        
        Returns:
            Status dictionary
        """
        return {
            'agent_id': self.agent_id,
            'running': self.running,
            'tasks': len(self.tasks),
            'type': self.__class__.__name__
        }
