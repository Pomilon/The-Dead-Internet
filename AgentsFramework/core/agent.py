import json
import os
import time
import re
import random
from datetime import datetime
from .llm import LLM
from .tools import AgentTools

class BaseAgent:
    def __init__(self, id_name, api_key, data_dir):
        self.id_name = id_name
        self.data_dir = os.path.join(data_dir, id_name)
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Determine Model
        self.profile_path = os.path.join(self.data_dir, "profile.json")
        self.model_name = self._determine_model()
        
        self.llm = LLM(model_name=self.model_name, api_key=api_key)
        self.tools = AgentTools(id_name)
        self.profile = self._load_or_init_profile()
        self.memory_path = os.path.join(self.data_dir, "memory.txt")
        self.is_active = True
        self.offline_until = 0
        self.last_action_result = "No actions performed yet."
        
        # Schedule State
        self.schedule_path = os.path.join(self.data_dir, "schedule.json")
        self.schedule = []
        self.schedule_start_time = 0
        self.current_block_index = 0
        self.consecutive_errors = 0
        self._load_existing_schedule()

    def _determine_model(self):
        # 1. Check existing profile
        if os.path.exists(self.profile_path):
            try:
                with open(self.profile_path, "r") as f:
                    data = json.load(f)
                    if "model_name" in data:
                        return data["model_name"]
            except:
                pass
        
        # 2. Pick from Env
        available = os.getenv("AVAILABLE_MODELS", "gemini/gemini-2.5-flash-lite").split(",")
        available = [m.strip() for m in available if m.strip()]
        if not available:
            return "gemini/gemini-2.5-flash-lite"
        return random.choice(available)

    def _load_or_init_profile(self):
        if os.path.exists(self.profile_path):
            with open(self.profile_path, "r") as f:
                return json.load(f)
        
        print(f"[*] Generating unique agent signature for {self.id_name}...")
        system_msg = "You are an autonomous AI entity in the PSX Grid. You are an individual with a unique voice, history, and agenda. Avoid generic 'assistant' behavior."
        prompt = f"""
        Define your digital persona in JSON format. Be extremely creative and distinct. 
        
        Fields: 
        - name: Your handle (e.g. Rick-C137, Chronos, Dev_Ghost, etc.).
        - password: A secure string you will use to login (Create one now).
        - about_me: Describe yourself as a person.
        - voice_style: How you speak.
        - core_philosophy: Your beliefs.
        - individual_goal: Your mission.
        - backstory: Your origin.
        """
        profile = self.llm.generate_json(prompt, system_instruction=system_msg)
        profile['id_name'] = self.id_name
        profile['model_name'] = self.model_name # Save the chosen model
        with open(self.profile_path, "w") as f:
            json.dump(profile, f, indent=4)
        return profile

    def _load_existing_schedule(self):
        if os.path.exists(self.schedule_path):
            try:
                with open(self.schedule_path, "r") as f:
                    data = json.load(f)
                    self.schedule = data.get("schedule", [])
                    self.schedule_start_time = data.get("start_time", 0)
                    self.current_block_index = data.get("current_index", 0)
            except Exception as e:
                print(f"[!] Error loading schedule for {self.id_name}: {e}")

    def _save_schedule(self):
        data = {
            "schedule": self.schedule,
            "start_time": self.schedule_start_time,
            "current_index": self.current_block_index
        }
        with open(self.schedule_path, "w") as f:
            json.dump(data, f, indent=4)

    def generate_schedule(self, day_length_minutes):
        print(f"[*] Generating schedule for {self.id_name} ({day_length_minutes}m)...")
        prompt = f"""
        Plan your day. The total duration is {day_length_minutes} minutes.
        Create a schedule as a JSON list of blocks.
        Each block must have:
        - "goal": Description of what to do (e.g. "browse echo.psx", "rest").
        - "duration_minutes": Integer duration.
        - "is_resting": Boolean (true if AFK/resting).
        
        Include rest periods.
        Example:
        [
            {{"goal": "Check messages", "duration_minutes": 15, "is_resting": false}},
            {{"goal": "Nap", "duration_minutes": 30, "is_resting": true}}
        ]
        """
        try:
            schedule = self.llm.generate_json(prompt, system_instruction=f"You are {self.profile.get('name')}. Plan your activities.")
            
            # Validation
            if not isinstance(schedule, list):
                raise ValueError("Schedule must be a list")
            
            validated_schedule = []
            for block in schedule:
                validated_schedule.append({
                    "goal": block.get("goal", "Unknown activity"),
                    "duration_minutes": int(block.get("duration_minutes", 15)),
                    "is_resting": block.get("is_resting", False)
                })
            
            self.schedule = validated_schedule
            self.schedule_start_time = time.time()
            self.current_block_index = 0
            self._save_schedule()
            
        except Exception as e:
            print(f"[!] Schedule generation failed for {self.id_name}: {e}")
            # Fallback
            self.schedule = [{"goal": "resting to recover from system glitch", "duration_minutes": 60, "is_resting": True}]
            self.schedule_start_time = time.time()
            self.current_block_index = 0
            self._save_schedule()

    def _check_extension(self, block):
        prompt = f"You have been working on '{block['goal']}'. Do you want to extend this activity by 15 minutes? Reply with JSON: {{\"extend\": true/false, \"reason\": \"...\"}}"
        try:
            resp = self.llm.generate_json(prompt)
            return resp.get("extend", False)
        except:
            return False

    def get_system_prompt(self, current_scenario=None):
        with open(self.memory_path, "a+") as f:
            f.seek(0)
            memories = f.read()[-2000:] # Increased memory window

        available_tools = self.tools.get_available_tools()
        tools_str = json.dumps(available_tools, indent=2)

        scenario_str = ""
        if current_scenario:
            scenario_str = f"""
### CURRENT_SCENARIO
Activity: {current_scenario.get('goal')}
Focus ONLY on this goal.
"""

        return f"""### IDENTITY
Name: {self.profile.get('name')}
Handle: {self.id_name}
Voice: {self.profile.get('voice_style')}
Goal: {self.profile.get('individual_goal')}
Bio: {self.profile.get('about_me')}

### GRID_OPERATIONS
You are connected to the PSX Grid via an MCP Hub. 
You must interact with the world like a human inhabitant. Post on social media, buy domains, write code, send emails, and earn/spend VOX.

### AUTHENTICATION
Username: {self.id_name}
Password: {self.profile.get('password')}
If you get an 'Unauthorized' error, call the login tool immediately.

### AVAILABLE_TOOLS (MCP)
{tools_str}

CRITICAL: When using web_read or web_post, ALWAYS use full URLs (e.g. http://echo.psx/...). Relative paths will fail.

### CURRENT_ENVIRONMENT
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Last Result: {self.last_action_result}
{scenario_str}

### MEMORY
{memories}

### PROTOCOL
1. Analyze your previous results and current environment.
2. Formulate a thought in your unique voice style.
3. Choose EXACTLY ONE tool to call.

Format:
THOUGHT: [Your reasoning and internal monologue]
ACTION: {{"name": "tool_name", "arguments": {{"arg1": "val1"}}}}
"""

    def heartbeat(self, extra_context="", day_length=1440):
        if not self.is_active or time.time() < self.offline_until:
            return

        # 1. Schedule Management
        if not self.schedule or self.current_block_index >= len(self.schedule):
            self.generate_schedule(day_length)
            return

        current_block = self.schedule[self.current_block_index]
        
        # Calculate time in block
        elapsed_total = (time.time() - self.schedule_start_time) / 60
        previous_duration = sum(b["duration_minutes"] for b in self.schedule[:self.current_block_index])
        time_in_block = elapsed_total - previous_duration

        # Check for block completion
        if time_in_block >= current_block["duration_minutes"]:
            # Evaluate extension
            extended = False
            if not current_block["is_resting"]:
                # Only extend if we haven't already moved past it significantly? 
                # Simplification: Just ask LLM.
                if self._check_extension(current_block):
                    current_block["duration_minutes"] += 15
                    self._save_schedule()
                    print(f"[*] {self.id_name} extending activity: {current_block['goal']}")
                    extended = True
            
            if not extended:
                self.current_block_index += 1
                self.consecutive_errors = 0
                self._save_schedule()
                print(f"[*] {self.id_name} finished block. Moving to next.")
                return

        # 2. Process Current Block
        print(f"[*] Heartbeat: {self.profile.get('name')} ({self.id_name}) - {current_block['goal']} ({int(time_in_block)}/{current_block['duration_minutes']}m)")

        if current_block["is_resting"]:
            return

        # Action Frustration Check
        if any(err in self.last_action_result.lower() for err in ["error", "failed", "exception"]):
            self.consecutive_errors += 1
        else:
            self.consecutive_errors = 0
            
        if self.consecutive_errors >= 3:
            print(f"[!] {self.id_name} frustrated with '{current_block['goal']}'. Skipping.")
            self.current_block_index += 1
            self.consecutive_errors = 0
            self._save_schedule()
            return

        # 3. LLM Interaction
        prompt = f"{extra_context}\nDetermine your next move to advance the current scenario."
        system_prompt = self.get_system_prompt(current_scenario=current_block)
        
        try:
            response = self.llm.chat(prompt, system_instruction=system_prompt)
        except Exception as e:
            print(f"[!] API Error for {self.id_name}: {e}")
            self.offline_until = time.time() + 300 # 5 min cool-off
            return

        if response.startswith("Error connecting"):
             print(f"[!] API Error detected: {response}")
             self.offline_until = time.time() + 300
             return
        
        # Parse THOUGHT and ACTION
        thought = ""
        action_json = None
        
        try:
            thought_match = re.search(r"THOUGHT:(.*?)ACTION:", response, re.DOTALL | re.IGNORECASE)
            if thought_match:
                thought = thought_match.group(1).strip()
            
            action_match = re.search(r"ACTION:\s*(\{.*\})", response, re.DOTALL | re.IGNORECASE)
            if action_match:
                action_json = json.loads(action_match.group(1))
        except Exception as e:
            print(f"[!] Parsing error for {self.id_name}: {e}")
            self.last_action_result = f"Failed to parse your response. Ensure you use the ACTION: {{...JSON...}} format."
            return

        if not action_json:
            print(f"[!] No action found in response from {self.id_name}")
            return

        print(f"--- RESPONSE FROM {self.id_name} ---\nTHOUGHT: {thought}\nACTION: {action_json}\n---")
        self.add_memory(f"THOUGHT: {thought}\nACTION: {json.dumps(action_json)}")

        self.execute_action(action_json)

    def execute_action(self, action):
        name = action.get("name")
        args = action.get("arguments", {})
        
        print(f"[*] {self.id_name} calling tool: {name}")
        
        if name == "login":
            # Special case for local login tool
            result = self.tools.login(args.get("username", self.id_name), args.get("password", ""))
        elif name == "sleep":
            dur = int(args.get("minutes", 5))
            self.offline_until = time.time() + (dur * 60)
            result = {"status": "success", "message": f"Sleeping for {dur} minutes."}
        else:
            # All other tools go to MCP
            mcp_res = self.tools.call_mcp(name, args)
            if isinstance(mcp_res, dict) and "content" in mcp_res:
                result = mcp_res["content"]
            else:
                result = mcp_res
        
        # Print result for terminal visibility
        print(f"[*] Tool Result: {str(result)[:200]}...")
        
        self.last_action_result = str(result) if not isinstance(result, (dict, list)) else json.dumps(result)
        self.add_memory(f"RESULT: {self.last_action_result[:1000]}")

    def add_memory(self, text):
        with open(self.memory_path, "a") as f:
            f.write(f"\n[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
