"""
LLM Client — Supports OpenAI, Anthropic, and Google Gemini APIs for threat analysis.
Handles API calls and response parsing.
"""

import json
import os
import re

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    from google import genai
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False


class LLMClient:
    """Unified LLM client supporting OpenAI, Anthropic, and Google Gemini."""

    def __init__(self, provider=None, api_key=None, model=None):
        # Auto-detect provider from environment if not specified
        self.provider = provider or os.getenv("LLM_PROVIDER", "")
        self.api_key = api_key
        self.model = model
        self._client = None

        self._setup_client()

    def _setup_client(self):
        """Initialize the appropriate LLM client."""
        if self.provider == "anthropic":
            if not self._try_anthropic():
                self._try_any_available()

        elif self.provider == "openai":
            if not self._try_openai():
                self._try_any_available()

        elif self.provider == "gemini":
            if not self._try_gemini():
                self._try_any_available()

        else:
            # No provider specified — auto-detect from available API keys
            self._try_any_available()

    def _try_any_available(self):
        """Try all providers in order until one works."""
        if self._client:
            return
        self._try_gemini()
        if self._client:
            return
        self._try_openai()
        if self._client:
            return
        self._try_anthropic()

    def _try_openai(self):
        key = self.api_key if self.provider == "openai" else None
        key = key or os.getenv("OPENAI_API_KEY", "")
        if key and HAS_OPENAI:
            self._client = openai.OpenAI(api_key=key)
            self.model = self.model or os.getenv("OPENAI_MODEL", "gpt-4o")
            self.provider = "openai"
            return True
        return False

    def _try_anthropic(self):
        key = self.api_key if self.provider == "anthropic" else None
        key = key or os.getenv("ANTHROPIC_API_KEY", "")
        if key and HAS_ANTHROPIC:
            self._client = anthropic.Anthropic(api_key=key)
            self.model = self.model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
            self.provider = "anthropic"
            return True
        return False

    def _try_gemini(self):
        key = self.api_key if self.provider == "gemini" else None
        key = key or os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")
        if key and HAS_GEMINI:
            self._client = genai.Client(api_key=key)
            self.model = self.model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
            self.provider = "gemini"
            return True
        return False

    @property
    def is_available(self):
        return self._client is not None

    def get_status(self):
        """Return current LLM configuration status."""
        return {
            "available": self.is_available,
            "provider": self.provider if self.is_available else None,
            "model": self.model if self.is_available else None,
            "message": f"Connected to {self.provider} ({self.model})" if self.is_available
                       else "No LLM configured. Set GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY."
        }

    def generate(self, system_prompt, user_prompt, temperature=0.3, max_tokens=4096):
        """
        Generate a response from the LLM.
        Returns the raw text response.
        """
        if not self.is_available:
            return None

        print(f"[LLM] 📡 Connecting to API: {self.provider} | Model: {self.model} ...", flush=True)

        try:
            if self.provider == "anthropic":
                messages = [{"role": "user", "content": user_prompt}]
                print(f"[LLM] 📤 Sending request to Anthropic Messages API...", flush=True)
                
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=messages
                )
                print(f"[LLM] ✅ Successfully received response from Anthropic!", flush=True)
                return response.content[0].text

            elif self.provider == "openai":
                response = self._client.chat.completions.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ]
                )
                return response.choices[0].message.content

            elif self.provider == "gemini":
                combined_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"
                response = self._client.models.generate_content(
                    model=self.model,
                    contents=combined_prompt,
                    config=genai.types.GenerateContentConfig(
                        temperature=temperature,
                        max_output_tokens=max_tokens
                    )
                )
                return response.text

        except Exception as e:
            print(f"\n[LLM CRITICAL ERROR] Failed to generate response from {self.provider}", flush=True)
            print(f"[LLM CRITICAL ERROR] Exception details: {type(e).__name__}: {str(e)}\n", flush=True)
            return None

    def generate_stream(self, system_prompt, user_prompt, temperature=0.3, max_tokens=4096):
        """
        Generator that yields chunks of text from the LLM as they stream in.
        """
        if not self.is_available:
            yield ""
            return

        print(f"[LLM STREAM] 📡 Connecting to API: {self.provider} | Model: {self.model} ...", flush=True)

        try:
            if self.provider == "anthropic":
                messages = [{"role": "user", "content": user_prompt}]
                with self._client.messages.stream(
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=messages
                ) as stream:
                    for text in stream.text_stream:
                        yield text

            elif self.provider == "openai":
                response = self._client.chat.completions.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    stream=True
                )
                for chunk in response:
                    if chunk.choices[0].delta.content:
                        yield chunk.choices[0].delta.content

            elif self.provider == "gemini":
                combined_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"
                response = self._client.models.generate_content(
                    model=self.model,
                    contents=combined_prompt,
                    config=genai.types.GenerateContentConfig(
                        temperature=temperature,
                        max_output_tokens=max_tokens
                    ),
                    stream=True
                )
                for chunk in response:
                    yield chunk.text

        except Exception as e:
            print(f"\n[LLM CRITICAL ERROR] Streaming failed from {self.provider}", flush=True)
            print(f"[LLM CRITICAL ERROR] Exception details: {type(e).__name__}: {str(e)}\n", flush=True)
            yield f"\n\n[Error: Connection dropped or failed during stream. See backend logs.]\n{str(e)}"

    def generate_json(self, system_prompt, user_prompt, temperature=0.3, max_tokens=4096):
        """
        Generate and parse a JSON response from the LLM.
        Handles markdown code blocks and partial JSON.
        Returns (parsed_json, raw_response_text).
        """
        raw = self.generate(system_prompt, user_prompt, temperature, max_tokens)
        if not raw:
            return None, None

        return self._parse_json_response(raw), raw

    @staticmethod
    def _parse_json_response(text):
        """Extract and parse JSON from LLM response text."""
        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Strip markdown code fences
        cleaned = text.strip()
        if cleaned.startswith('```'):
            first_nl = cleaned.find('\n')
            if first_nl != -1:
                cleaned = cleaned[first_nl + 1:]
        if cleaned.rstrip().endswith('```'):
            cleaned = cleaned.rstrip()[:-3]
        cleaned = cleaned.strip()

        # Try parsing the fence-stripped text
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Extract from first { to last } (handles extra text around JSON)
        start = cleaned.find('{')
        if start != -1:
            end = cleaned.rfind('}')
            if end > start:
                try:
                    return json.loads(cleaned[start:end + 1])
                except json.JSONDecodeError:
                    pass

            # JSON likely truncated (hit max_tokens) — try to repair
            repaired = LLMClient._repair_truncated_json(cleaned[start:])
            try:
                return json.loads(repaired)
            except json.JSONDecodeError:
                pass

        print(f"[LLM Warning] Could not parse JSON from response: {text[:200]}...")
        return None

    @staticmethod
    def _repair_truncated_json(text):
        """Repair truncated JSON by closing open strings, brackets, and braces."""
        in_string = False
        escape_next = False
        stack = []

        for ch in text:
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '{':
                stack.append('}')
            elif ch == '[':
                stack.append(']')
            elif ch in '}]' and stack:
                stack.pop()

        result = text
        # Close any open string
        if in_string:
            result += '"'
        # Close all open brackets/braces in reverse order
        while stack:
            result += stack.pop()

        return result
