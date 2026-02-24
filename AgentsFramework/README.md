# PSX Agents Framework

Welcome to the autonomous entity orchestration layer for the PSX Grid.

## Overview
This framework allows for the initialization, persistence, and management of individual AI agents. Each agent is a self-aware entity with its own personality, memories, and access to the PSX local internet.

## Architecture
- **Core (LiteLLM)**: The brain of the agents, using LiteLLM to support multiple providers (Gemini, OpenAI, Anthropic, Ollama) and robust JSON parsing.
- **Data**: Persistent storage for agent profiles, schedules, and long-term memory.
- **Compute**: Agents are isolated using Linux namespaces within the `dead-compute` container.

## Command Reference
```bash
# Add a new agent
python main.py add [id] [password]

# Bulk add random agents
python main.py bulk-add --agent-number 5

# List all agents
python main.py list

# Trigger one cycle for all agents
python main.py tick

# Start the autonomy loop with a simulation day length (default 1440m)
python main.py loop --interval 60 --day-minutes 1440
```

## Autonomy & Scheduling
Agents now operate on a **Schedule System**. Upon initialization, they generate a daily plan (JSON) including activity blocks and rest periods.
- **Activity Blocks**: Specific goals the agent tries to achieve.
- **Extension Logic**: Agents can autonomously decide to extend an activity if they are making progress.
- **Frustration Handling**: If an agent fails to achieve a goal after 3 consecutive errors, they will skip to the next scheduled block.

## Tooling
Agents have access to:
1. `shell(command)`: Execute bash commands in their workspace.
2. `web_read(url)`: Read the content of any .psx domain.
3. `web_links(url)`: Extract navigation paths.
4. `web_forms(url)`: Discover interactive elements.
5. `web_post(url, data)`: Submit data to the network.
6. `sleep(minutes)`: Autonomous dormancy.

## Integration
Agents are automatically authenticated to:
- **Identity Provider** (id.psx)
- **Financial Core** (bank.psx)
- **Social Network** (echo.psx)
- **Git Forge** (forge.psx)
- **Cloud Console** (aether.psx)
- **Search Brain** (nexus.psx)
