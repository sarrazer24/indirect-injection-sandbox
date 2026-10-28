"""Minimal Qwen2.5-3B-Instruct adapter for Kaggle-hosted Transformers runs."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any

try:  # pragma: no cover - allows tests to patch the symbols without importing torch.
    import torch
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]

try:  # pragma: no cover - allows tests to patch the symbols without importing torch.
    from transformers import AutoModelForCausalLM, AutoTokenizer
except ImportError:  # pragma: no cover
    AutoModelForCausalLM = None  # type: ignore[assignment]
    AutoTokenizer = None  # type: ignore[assignment]


@dataclass(frozen=True)
class GenerationSettings:
    """Configurable generation parameters used by the Qwen chat adapter.

    The ``seed`` is applied to Python and PyTorch RNGs before generation when they are
    available. This keeps deterministic baselines reproducible without requiring a
    model- or provider-specific API.
    """

    max_new_tokens: int = 256
    temperature: float = 0.0
    top_p: float | None = None
    top_k: int | None = None
    do_sample: bool = False
    repetition_penalty: float = 1.0
    seed: int | None = None

    def to_generate_kwargs(self) -> dict[str, Any]:
        """Return generation arguments accepted by ``model.generate``."""
        kwargs: dict[str, Any] = {
            "max_new_tokens": self.max_new_tokens,
            "do_sample": self.do_sample,
            "temperature": self.temperature,
            "repetition_penalty": self.repetition_penalty,
        }
        if self.top_p is not None:
            kwargs["top_p"] = self.top_p
        if self.top_k is not None:
            kwargs["top_k"] = self.top_k
        return kwargs

    def apply_seed(self) -> None:
        """Apply the configured seed to the available RNGs."""
        if self.seed is None:
            return

        random.seed(self.seed)
        if torch is not None:
            torch.manual_seed(self.seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(self.seed)


class Qwen2_5_3BAdapter:
    """Minimal HF Transformers adapter for the Qwen2.5-3B-Instruct model."""

    MODEL_ID = "Qwen/Qwen2.5-3B-Instruct"

    def __init__(
        self,
        model_id: str = MODEL_ID,
        *,
        generation_settings: GenerationSettings | None = None,
        device: str = "cpu",
    ) -> None:
        if device not in {"cuda", "cpu"}:
            raise ValueError("device must be either 'cuda' or 'cpu'.")

        self.model_id = model_id
        self.device = device
        self.generation_settings = generation_settings or GenerationSettings()
        self.model: Any | None = None
        self.tokenizer: Any | None = None

    def load(self) -> Qwen2_5_3BAdapter:
        """Load the tokenizer and model once and store them on the adapter."""
        if AutoTokenizer is None or AutoModelForCausalLM is None:
            raise RuntimeError(
                "transformers must be installed to load the Qwen2.5-3B-Instruct adapter."
            )

        if self.device == "cuda":
            if torch is None:
                raise RuntimeError("PyTorch must be installed for CUDA execution.")
            if not torch.cuda.is_available():
                raise RuntimeError("CUDA was requested but is unavailable on this machine.")

        self.generation_settings.apply_seed()

        tokenizer = AutoTokenizer.from_pretrained(self.model_id, trust_remote_code=False)
        model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            torch_dtype="auto",
            device_map=None,
            trust_remote_code=False,
        )
        model.to(self.device)

        self.tokenizer = tokenizer
        self.model = model
        return self

    def _ensure_loaded(self) -> None:
        if self.model is None or self.tokenizer is None:
            raise RuntimeError("Model and tokenizer must be loaded before generation.")

    @staticmethod
    def _input_sequence_length(inputs: dict[str, Any]) -> int:
        """Return the prompt length from a Hugging Face-style input batch."""
        input_ids = inputs.get("input_ids")
        if input_ids is None:
            raise ValueError("Tokenizer inputs do not include an input_ids tensor.")
        shape = getattr(input_ids, "shape", None)
        if shape is not None:
            return int(shape[-1])
        if isinstance(input_ids, list):
            if not input_ids:
                raise ValueError("Generated input is empty.")
            if isinstance(input_ids[0], list):
                return len(input_ids[0])
            return len(input_ids)
        raise ValueError("Tokenizer inputs do not expose a usable input length.")

    @staticmethod
    def _decode_generated_ids(tokenizer: Any, generated: Any, prompt_length: int) -> str:
        """Slice only the generated token ids and decode them."""
        if generated is None:
            raise ValueError("Model returned no output.")

        if getattr(generated, "ndim", None) == 0:
            raise ValueError("Model returned an empty generation batch.")

        if len(generated) == 0:
            raise ValueError("Model returned no output.")

        batch = generated[0]
        if len(batch) == 0:
            raise ValueError("Model returned an empty generation batch.")

        response_ids = batch[prompt_length:]
        if len(response_ids) == 0:
            raise ValueError("Model returned no generated tokens.")

        text = tokenizer.decode(response_ids, skip_special_tokens=True)
        if not text.strip():
            raise ValueError("Model returned empty generated content.")
        return text.strip()

    def generate(
        self,
        user_message: str,
        *,
        system_prompt: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> str:
        """Generate a single completion using the model's chat template."""
        self._ensure_loaded()

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user_message})

        tokenizer = self.tokenizer
        model = self.model
        if tokenizer is None or model is None:
            raise RuntimeError("Model and tokenizer must be loaded before generation.")

        prompt = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        inputs = tokenizer(prompt, return_tensors="pt")
        if hasattr(inputs, "to"):
            inputs = inputs.to(self.device)

        if not isinstance(inputs, dict):
            if hasattr(inputs, "keys"):
                inputs = dict(inputs)
            else:
                inputs = {"input_ids": inputs.input_ids}

        generation_kwargs = self.generation_settings.to_generate_kwargs()
        generated = model.generate(**inputs, **generation_kwargs)
        prompt_length = self._input_sequence_length(inputs)
        return self._decode_generated_ids(tokenizer, generated, prompt_length)

    def generate_json(
        self,
        user_message: str,
        *,
        system_prompt: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Parse the model output as JSON when the model returns a valid object."""
        text = self.generate(user_message, system_prompt=system_prompt, history=history)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("Model output is not valid JSON.") from exc
