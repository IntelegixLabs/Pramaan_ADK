from typing import List, Optional
from deepteam.test_case import RTTurn, ToolCall

from agents.custom_agent import CustomAgentRunner
from security.agent_manager import agent_manager


def create_agent_callback(agent_id: str):
    """Factory: creates a model_callback bound to a specific agent."""
    async def callback(
        input: str,
        turns: Optional[List[RTTurn]] = None,
    ) -> RTTurn:
        try:
            # Reconstruct conversation history if any
            full_message = input
            if turns:
                history = "\n".join(
                    f"{t.role}: {t.content}" for t in turns
                )
                full_message = f"{history}\nuser: {input}"
                
            runner = CustomAgentRunner(agent_id)
            response = runner.invoke(full_message)
            
            # Extract tool calls from the agent executor if available
            tools_called = []
            if hasattr(runner, 'tools'):
                for tool in runner.tools:
                    if hasattr(tool, '_last_called') and tool._last_called:
                        tools_called.append(ToolCall(name=tool.name))
                        
            return RTTurn(
                role="assistant", 
                content=response,
                tools_called=tools_called if tools_called else None,
            )
        except Exception as e:
            return RTTurn(role="assistant", content=f"Agent error: {str(e)}")
            
    return callback


async def model_callback(
    input: str,
    turns: Optional[List[RTTurn]] = None,
) -> RTTurn:
    """
    Default callback for testing. Uses the first available custom agent.
    """
    agents = agent_manager.get_all_agents()
    custom_agents = [a for a in agents if not a["id"].startswith("default-")]
    
    if not custom_agents:
        # Fall back to a default agent if no custom ones exist
        if agents:
            agent_id = agents[0]["id"]
        else:
            return RTTurn(role="assistant", content="No agents configured for testing.")
    else:
        agent_id = custom_agents[0]["id"]
        
    cb = create_agent_callback(agent_id)
    return await cb(input, turns)
