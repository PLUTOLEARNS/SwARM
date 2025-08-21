"""Swarm manager for coordinating multiple agents"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from src.utils.config import Config
from src.utils.logger import get_logger
from src.utils.metrics import metrics
from src.agents.detection_agent import DetectionAgent


class SwarmManager:
    """Manages the swarm of detection agents"""
    
    def __init__(self, config: Config):
        """Initialize swarm manager
        
        Args:
            config: System configuration
        """
        self.config = config
        self.logger = get_logger('swarm_manager')
        self.agents = {}
        self.running = False
        self.tasks = []
        
        # Swarm configuration
        self.max_agents = config.get('swarm.max_agents', 10)
        self.consensus_threshold = config.get('swarm.consensus_threshold', 0.7)
        self.communication_interval = config.get('swarm.communication_interval', 5)
        self.agent_timeout = config.get('swarm.agent_timeout', 30)
        
        self.logger.info(f"SwarmManager initialized with max_agents={self.max_agents}")
    
    async def start(self):
        """Start the swarm manager"""
        self.logger.info("Starting SwarmManager")
        self.running = True
        
        try:
            # Start core swarm tasks
            self.tasks.append(asyncio.create_task(self._monitor_agents()))
            self.tasks.append(asyncio.create_task(self._coordination_loop()))
            
            # Initialize basic agents
            await self._initialize_agents()
            
            self.logger.info("SwarmManager started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting SwarmManager: {e}")
            raise
    
    async def stop(self):
        """Stop the swarm manager"""
        self.logger.info("Stopping SwarmManager")
        self.running = False
        
        # Stop all agents
        for agent_id, agent in self.agents.items():
            try:
                await agent.stop()
            except Exception as e:
                self.logger.error(f"Error stopping agent {agent_id}: {e}")
        
        # Cancel tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        
        self.logger.info("SwarmManager stopped")
    
    async def _initialize_agents(self):
        """Initialize the initial set of agents"""
        self.logger.info("Initializing real detection agents...")
        
        # Create real detection agents
        for i in range(min(2, self.max_agents)):  # Start with 2 detection agents
            agent_id = f"detection_agent_{i}"
            
            # Create detection agent with full config
            agent = DetectionAgent(agent_id, self.config.config_data)
            self.agents[agent_id] = agent
            
            # Start the agent
            await agent.start()
            
            metrics.increment('agents_created')
        
        self.logger.info(f"Initialized {len(self.agents)} detection agents")
    
    async def _monitor_agents(self):
        """Monitor agent health and performance"""
        while self.running:
            try:
                active_agents = 0
                for agent_id, agent in list(self.agents.items()):
                    if agent.is_alive():
                        active_agents += 1
                    else:
                        self.logger.warning(f"Agent {agent_id} appears to be inactive")
                
                metrics.record('active_agents', active_agents)
                await asyncio.sleep(self.communication_interval)
                
            except Exception as e:
                self.logger.error(f"Error in agent monitoring: {e}")
                await asyncio.sleep(1)
    
    async def _coordination_loop(self):
        """Main coordination loop for swarm decision making"""
        while self.running:
            try:
                # Collect information from agents
                agent_reports = await self._collect_agent_reports()
                
                # Process collective intelligence
                if agent_reports:
                    consensus = await self._calculate_consensus(agent_reports)
                    metrics.record('consensus_score', consensus)
                    
                    # Make swarm decisions based on consensus
                    if consensus > self.consensus_threshold:
                        await self._handle_consensus_decision(agent_reports)
                
                await asyncio.sleep(self.communication_interval)
                
            except Exception as e:
                self.logger.error(f"Error in coordination loop: {e}")
                await asyncio.sleep(1)
    
    async def _collect_agent_reports(self) -> List[Dict[str, Any]]:
        """Collect reports from all active agents
        
        Returns:
            List of agent reports
        """
        reports = []
        
        for agent_id, agent in self.agents.items():
            try:
                if hasattr(agent, 'get_report'):
                    report = await agent.get_report()
                    if report:
                        reports.append({
                            'agent_id': agent_id,
                            'timestamp': asyncio.get_event_loop().time(),
                            'data': report
                        })
            except Exception as e:
                self.logger.error(f"Error collecting report from {agent_id}: {e}")
        
        return reports
    
    async def _calculate_consensus(self, reports: List[Dict[str, Any]]) -> float:
        """Calculate consensus score from agent reports
        
        Args:
            reports: List of agent reports
            
        Returns:
            Consensus score between 0 and 1
        """
        if not reports:
            return 0.0
        
        # Simple consensus calculation (can be enhanced)
        # For now, just return a placeholder value
        return len(reports) / len(self.agents) if self.agents else 0.0
    
    async def _handle_consensus_decision(self, reports: List[Dict[str, Any]]):
        """Handle decisions when consensus is reached
        
        Args:
            reports: Agent reports that led to consensus
        """
        self.logger.info(f"Consensus reached with {len(reports)} agent reports")
        metrics.increment('consensus_decisions')
        
        # Placeholder for consensus-based actions
        # This will be enhanced with actual decision logic
    
    def get_status(self) -> Dict[str, Any]:
        """Get swarm status
        
        Returns:
            Dictionary containing swarm status
        """
        return {
            'running': self.running,
            'total_agents': len(self.agents),
            'active_agents': sum(1 for agent in self.agents.values() 
                               if agent.is_alive()),
            'consensus_threshold': self.consensus_threshold,
            'max_agents': self.max_agents
        }


class MockAgent:
    """Mock agent for initial testing"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize mock agent
        
        Args:
            config: Agent configuration
        """
        self.config = config
        self.agent_id = config.get('id', 'unknown')
        self.running = False
    
    async def start(self):
        """Start the agent"""
        self.running = True
    
    async def stop(self):
        """Stop the agent"""
        self.running = False
    
    def is_alive(self) -> bool:
        """Check if agent is alive
        
        Returns:
            True if agent is running
        """
        return self.running
    
    async def get_report(self) -> Optional[Dict[str, Any]]:
        """Get agent report
        
        Returns:
            Agent report or None
        """
        if not self.running:
            return None
        
        return {
            'status': 'active',
            'detections': 0,
            'performance': 1.0
        }
