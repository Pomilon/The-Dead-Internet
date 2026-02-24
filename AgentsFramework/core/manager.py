import json
import os
import subprocess
import time
import requests
import random
import string
from .agent import BaseAgent

class AgentManager:
    def __init__(self, api_key, data_dir="data"):
        self.api_key = api_key
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.agents = {}
        self._load_existing_agents()

    def _load_existing_agents(self):
        # Scan data dir for profiles
        if not os.path.exists(self.data_dir): return
        for d in os.listdir(self.data_dir):
            if os.path.isdir(os.path.join(self.data_dir, d)):
                self.agents[d] = BaseAgent(d, self.api_key, self.data_dir)

    def create_agent(self, id_name, password):
        """Creates a real agent: Linux user, PSX ID, and Framework instance."""
        print(f"[*] Provisioning Agent {id_name}...")
        
        # 1. Create Linux user and PSX ID inside the container
        cmd = ["docker", "exec", "dead-compute", "/app/agent_manager.py", id_name, password]
        try:
            subprocess.run(cmd, check=True)
        except Exception as e:
            print(f"[!] Error provisioning container resources: {e}")
            return None

        # 2. Create framework instance
        agent = BaseAgent(id_name, self.api_key, self.data_dir)
        # Update profile with provided password for login consistency
        agent.profile['password'] = password
        with open(os.path.join(agent.data_dir, "profile.json"), "w") as f:
            json.dump(agent.profile, f, indent=4)
            
        self.agents[id_name] = agent
        return agent

    def bulk_create_agents(self, count):
        print(f"[*] Starting bulk creation of {count} agents...")
        
        for _ in range(count):
            # Generate random ID
            suffix = ''.join(random.choices(string.digits, k=4))
            id_name = f"User_{suffix}"
            
            # Ensure uniqueness
            while id_name in self.agents:
                 suffix = ''.join(random.choices(string.digits, k=4))
                 id_name = f"User_{suffix}"

            # Generate random password
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            
            self.create_agent(id_name, password)
            # Small delay to avoid race conditions or overload
            time.sleep(1)

    def remove_agent(self, id_name):
        if id_name in self.agents:
            del self.agents[id_name]
            print(f"[*] Agent {id_name} removed from active session.")

    def run_heartbeat(self, day_length=1440):
        """Ticks every active agent once."""
        print(f"\n--- HEARTBEAT START ({len(self.agents)} active) ---")
        
        # 1. Fetch Global Context (Latest from Echo)
        global_context = ""
        try:
            r = requests.get("http://echo.psx/api/feed", params={"limit": 10}, timeout=5)
            if r.status_code == 200:
                feed = r.json()
                context_str = "\n".join([f"POST (ID: {p.get('id')}): {p.get('title')} by {p.get('author')}" for p in feed])
                global_context = f"\n# GLOBAL_SIGNAL (Recent Echo Transmissions)\n{context_str}\n"
        except Exception as e:
            print(f"[*] Could not fetch global context: {e}")

        # 2. Tick Agents
        for agent in self.agents.values():
            try:
                # Pass global context to the heartbeat
                agent.heartbeat(extra_context=global_context, day_length=day_length)
                # Small delay to avoid rate limits
                time.sleep(15)
            except Exception as e:
                print(f"[!] Heartbeat failed for {agent.id_name}: {e}")
        print("--- HEARTBEAT END ---\n")

    def list_agents(self):
        return [
            {"id": a.id_name, "name": a.profile.get('name'), "active": a.is_active}
            for a in self.agents.values()
        ]
