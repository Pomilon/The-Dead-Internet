import json
import os
import re
from litellm import completion

class LLM:
    def __init__(self, model_name="gemini/gemini-2.5-flash-lite", api_key=None):
        self.model_name = model_name
        self.api_key = api_key
        # litellm handles API keys via environment variables usually.
        # If api_key is provided and valid for the model, it can be passed, 
        # but for multi-provider it's better to rely on env vars.
        # We'll set the GEMINI_API_KEY env var if it's not set and we have a key,
        # just to preserve behavior if users rely on the CLI arg/env var logic from main.py
        if self.api_key and "gemini" in self.model_name and not os.getenv("GEMINI_API_KEY"):
             os.environ["GEMINI_API_KEY"] = self.api_key

    def chat(self, prompt, system_instruction=None, history=None):
        messages = []
        
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
            
        if history:
            for msg in history:
                messages.append({"role": msg["role"], "content": msg["content"]})
        
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = completion(
                model=self.model_name,
                messages=messages,
                temperature=0.9,
                max_tokens=2048
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"LLM API Error ({self.model_name}): {e}")
            return f"Error connecting to LLM API: {str(e)}"

    def generate_json(self, prompt, system_instruction=None):
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        
        messages.append({"role": "user", "content": prompt})
        
        try:
            # Some providers support response_format={"type": "json_object"}, 
            # but to be generic across Ollama/LlamaCpp/etc, we'll rely on prompt engineering 
            # and our robust parsing.
            response = completion(
                model=self.model_name,
                messages=messages,
                temperature=0.7,
                # response_format={"type": "json_object"}, # Optional: enable if only using providers that support it
            )
            text = response.choices[0].message.content

            # Robust JSON parsing: Strip markdown code blocks if present
            cleaned_text = text.strip()
            # Remove ```json ... ``` or ``` ... ``` wrappers
            if cleaned_text.startswith("```"):
                cleaned_text = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned_text, flags=re.MULTILINE)
            
            try:
                return json.loads(cleaned_text)
            except json.JSONDecodeError:
                # Fallback: Find the first { or [ and last } or ] if garbage surrounds the JSON
                match = re.search(r"(\{.*\}|\[.*\])", cleaned_text, re.DOTALL)
                if match:
                    return json.loads(match.group(1))
                raise
        except Exception as e:
            print(f"LLM JSON Error ({self.model_name}): {e}")
            return {"error": "Failed to parse JSON", "exception": str(e)}
