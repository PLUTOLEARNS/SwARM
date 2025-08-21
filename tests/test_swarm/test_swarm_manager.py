"""Tests for SwarmManager"""

import pytest
import asyncio
from unittest.mock import MagicMock
from src.utils.config import Config
from src.swarm.swarm_manager import SwarmManager, MockAgent


class TestSwarmManager:
    """Test cases for SwarmManager class"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        config = Config()
        config.set('swarm.max_agents', 5)
        config.set('swarm.consensus_threshold', 0.6)
        config.set('swarm.communication_interval', 1)
        return config
    
    @pytest.fixture
    def swarm_manager(self, config):
        """Create SwarmManager instance for testing"""
        return SwarmManager(config)
    
    def test_initialization(self, swarm_manager, config):
        """Test SwarmManager initialization"""
        assert swarm_manager.config == config
        assert swarm_manager.max_agents == 5
        assert swarm_manager.consensus_threshold == 0.6
        assert swarm_manager.communication_interval == 1
        assert not swarm_manager.running
        assert len(swarm_manager.agents) == 0
    
    @pytest.mark.asyncio
    async def test_start_stop(self, swarm_manager):
        """Test starting and stopping SwarmManager"""
        # Start manager
        start_task = asyncio.create_task(swarm_manager.start())
        await asyncio.sleep(0.1)  # Let it initialize
        
        assert swarm_manager.running
        assert len(swarm_manager.agents) > 0
        
        # Stop manager
        await swarm_manager.stop()
        await start_task
        
        assert not swarm_manager.running
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, swarm_manager):
        """Test agent initialization"""
        await swarm_manager._initialize_agents()
        
        # Should create 2 detection agents (min of 2 and max_agents=5)
        assert len(swarm_manager.agents) == 2
        
        # Check agent IDs
        expected_ids = ['detection_agent_0', 'detection_agent_1']
        assert set(swarm_manager.agents.keys()) == set(expected_ids)
        
        # Stop agents to clean up
        for agent in swarm_manager.agents.values():
            await agent.stop()
    
    @pytest.mark.asyncio
    async def test_collect_agent_reports(self, swarm_manager):
        """Test collecting reports from agents"""
        # Initialize agents
        await swarm_manager._initialize_agents()
        
        # Collect reports (detection agents should provide reports when running)
        reports = await swarm_manager._collect_agent_reports()
        
        assert len(reports) == len(swarm_manager.agents)
        
        for report in reports:
            assert 'agent_id' in report
            assert 'timestamp' in report
            assert 'data' in report
            assert report['data']['status'] == 'active'
        
        # Stop agents to clean up
        for agent in swarm_manager.agents.values():
            await agent.stop()
    
    @pytest.mark.asyncio
    async def test_consensus_calculation(self, swarm_manager):
        """Test consensus calculation"""
        # Initialize agents
        await swarm_manager._initialize_agents()
        
        # Create mock reports
        reports = [
            {'agent_id': 'agent_0', 'data': {'status': 'active'}},
            {'agent_id': 'agent_1', 'data': {'status': 'active'}},
        ]
        
        consensus = await swarm_manager._calculate_consensus(reports)
        
        # Should be 2/3 = 0.67 (2 reports from 3 agents)
        expected = len(reports) / len(swarm_manager.agents)
        assert consensus == expected
    
    def test_get_status(self, swarm_manager):
        """Test getting swarm status"""
        status = swarm_manager.get_status()
        
        assert 'running' in status
        assert 'total_agents' in status
        assert 'active_agents' in status
        assert 'consensus_threshold' in status
        assert 'max_agents' in status
        
        assert status['running'] == swarm_manager.running
        assert status['consensus_threshold'] == swarm_manager.consensus_threshold
        assert status['max_agents'] == swarm_manager.max_agents


class TestMockAgent:
    """Test cases for MockAgent class"""
    
    @pytest.fixture
    def agent_config(self):
        """Create agent configuration"""
        return {
            'id': 'test_agent',
            'type': 'detection',
            'config': Config()
        }
    
    @pytest.fixture
    def mock_agent(self, agent_config):
        """Create MockAgent instance"""
        return MockAgent(agent_config)
    
    def test_initialization(self, mock_agent):
        """Test MockAgent initialization"""
        assert mock_agent.agent_id == 'test_agent'
        assert not mock_agent.running
    
    @pytest.mark.asyncio
    async def test_start_stop(self, mock_agent):
        """Test starting and stopping agent"""
        assert not mock_agent.is_alive()
        
        await mock_agent.start()
        assert mock_agent.is_alive()
        
        await mock_agent.stop()
        assert not mock_agent.is_alive()
    
    @pytest.mark.asyncio
    async def test_get_report(self, mock_agent):
        """Test getting agent report"""
        # Should return None when not running
        report = await mock_agent.get_report()
        assert report is None
        
        # Should return report when running
        await mock_agent.start()
        report = await mock_agent.get_report()
        
        assert report is not None
        assert 'status' in report
        assert 'detections' in report
        assert 'performance' in report
        assert report['status'] == 'active'
