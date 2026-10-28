"""LLM backends for Foundation-Sec-8B-Instruct, picked by GPU tier.

- L4 / A100 (bf16-capable, >= 20 GB): bf16 weights; vLLM on A100 when it is installed.
- T4 and other smaller CUDA GPUs: 4-bit NF4 via bitsandbytes.
- No GPU, or any load failure: no backend, so the caller falls back to the replay agent.

Decoding is greedy (temperature 0). Heavy imports (torch, transformers, vllm) are lazy so the
package stays importable without the `llm` extra.
"""

from __future__ import annotations

import importlib.util
import logging
from dataclasses import dataclass
from typing import Literal, Protocol

from ..config import LLMBackend, Settings

log = logging.getLogger(__name__)

MODEL_ID = "fdtn-ai/Foundation-Sec-8B-Instruct"
DEFAULT_MAX_NEW_TOKENS = 256
BF16_MIN_VRAM_GB = 20.0
NF4_MIN_VRAM_GB = 6.0

Tier = Literal["bf16", "4bit", "vllm", "replay"]
Message = dict[str, str]


class ChatBackend(Protocol):
    """Anything that turns a chat history into the next assistant message."""

    name: str

    def generate(self, messages: list[Message]) -> str: ...


class BackendError(RuntimeError):
    """The model could not be loaded or failed to generate."""


@dataclass(frozen=True)
class GPUInfo:
    name: str
    vram_gb: float
    compute_capability: tuple[int, int]

    @property
    def bf16(self) -> bool:
        return self.compute_capability >= (8, 0)


@dataclass(frozen=True)
class TierChoice:
    tier: Tier
    reason: str


def detect_gpu() -> GPUInfo | None:
    """The first CUDA device, or None when torch or CUDA is unavailable."""
    try:
        import torch
    except ImportError:
        return None
    if not torch.cuda.is_available():
        return None
    props = torch.cuda.get_device_properties(0)
    return GPUInfo(props.name, props.total_memory / 1024**3, (props.major, props.minor))


def _has(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def select_tier(
    requested: LLMBackend, gpu: GPUInfo | None, vllm_available: bool | None = None
) -> TierChoice:
    """Map the configured backend and the detected GPU to a concrete tier."""
    if vllm_available is None:
        vllm_available = _has("vllm")
    if requested == "replay":
        return TierChoice("replay", "replay requested")
    if gpu is None:
        return TierChoice("replay", "no CUDA GPU")
    if requested == "vllm":
        if vllm_available:
            return TierChoice("vllm", "vLLM requested")
        requested = "auto"
    if requested in ("bf16", "4bit"):
        return TierChoice(requested, f"{requested} requested on {gpu.name}")
    if gpu.bf16 and gpu.vram_gb >= BF16_MIN_VRAM_GB:
        if "A100" in gpu.name.upper() and vllm_available:
            return TierChoice("vllm", f"{gpu.name}: vLLM bf16")
        return TierChoice("bf16", f"{gpu.name} ({gpu.vram_gb:.0f} GB): bf16")
    if gpu.vram_gb >= NF4_MIN_VRAM_GB:
        return TierChoice("4bit", f"{gpu.name} ({gpu.vram_gb:.0f} GB): 4-bit NF4")
    return TierChoice("replay", f"{gpu.name} has only {gpu.vram_gb:.1f} GB VRAM")


class TransformersBackend:
    """Hugging Face transformers, bf16 or 4-bit NF4, greedy decoding."""

    def __init__(
        self,
        quant: Literal["bf16", "4bit"],
        model_id: str = MODEL_ID,
        token: str | None = None,
        max_new_tokens: int = DEFAULT_MAX_NEW_TOKENS,
    ) -> None:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.name = f"transformers-{quant}"
        self.max_new_tokens = max_new_tokens
        kwargs: dict = {"device_map": "auto", "token": token or None}
        if quant == "4bit":
            from transformers import BitsAndBytesConfig

            # T4 has no bf16, so compute in fp16.
            kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.float16,
            )
        else:
            kwargs["dtype"] = torch.bfloat16
        self.tokenizer = AutoTokenizer.from_pretrained(model_id, token=token or None)
        self.model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
        self.model.eval()

    def generate(self, messages: list[Message]) -> str:
        import torch

        prompt = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = self.tokenizer(prompt, return_tensors="pt", add_special_tokens=False)
        inputs = inputs.to(self.model.device)
        with torch.inference_mode():
            out = self.model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id or self.tokenizer.eos_token_id,
            )
        new_tokens = out[0, inputs["input_ids"].shape[1] :]
        return self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()


class VLLMBackend:
    """vLLM offline engine (A100), bf16, temperature 0."""

    def __init__(
        self,
        model_id: str = MODEL_ID,
        token: str | None = None,
        max_new_tokens: int = DEFAULT_MAX_NEW_TOKENS,
    ) -> None:
        import os

        from vllm import LLM, SamplingParams

        if token:
            os.environ.setdefault("HF_TOKEN", token)
        self.name = "vllm-bf16"
        self.llm = LLM(model=model_id, dtype="bfloat16", max_model_len=8192)
        self.params = SamplingParams(temperature=0.0, max_tokens=max_new_tokens)

    def generate(self, messages: list[Message]) -> str:
        out = self.llm.chat(messages, self.params, use_tqdm=False)
        return out[0].outputs[0].text.strip()


def build_backend(tier: Tier, settings: Settings, model_id: str = MODEL_ID) -> ChatBackend | None:
    token = settings.hf_token or None
    if tier == "vllm":
        return VLLMBackend(model_id, token)
    if tier in ("bf16", "4bit"):
        return TransformersBackend(tier, model_id, token)  # type: ignore[arg-type]
    return None


def load_backend(
    settings: Settings | None = None, model_id: str = MODEL_ID
) -> tuple[ChatBackend | None, TierChoice]:
    """Pick a tier and load the model. Returns (None, choice) when the replay agent should run;
    a failed load falls back to replay with the error in `choice.reason`."""
    settings = settings or Settings.from_env()
    choice = select_tier(settings.llm_backend, detect_gpu())
    log.info("LLM tier: %s (%s)", choice.tier, choice.reason)
    try:
        return build_backend(choice.tier, settings, model_id), choice
    except Exception as exc:  # noqa: BLE001 - any load failure means "use replay"
        log.warning("LLM load failed on tier %s: %s", choice.tier, exc)
        return None, TierChoice("replay", f"{choice.tier} load failed: {exc}")
