import json

import pytest

from injection_sandbox.agent import qwen_adapter
from injection_sandbox.agent.qwen_adapter import GenerationSettings, Qwen2_5_3BAdapter


class FakeInputBatch(dict):
    def __init__(self, prompt: str):
        self.prompt = prompt
        self.device = "cpu"
        self["input_ids"] = [[1, 2, 3, 4]]

    @property
    def shape(self):
        return (1, len(self["input_ids"][0]))

    def to(self, device: str):
        self.device = device
        return self


class FakeTokenizer:
    def __init__(self, *, decode_result: str = '{"ok": true}'):
        self.messages = None
        self.decode_calls = []
        self.decode_result = decode_result

    def from_pretrained(self, model_id, trust_remote_code=False):
        assert model_id == "Qwen/Qwen2.5-3B-Instruct"
        assert trust_remote_code is False
        return self

    def apply_chat_template(self, messages, tokenize=False, add_generation_prompt=True):
        self.messages = messages
        assert tokenize is False
        assert add_generation_prompt is True
        return "chat-template:" + json.dumps(messages)

    def __call__(self, prompt, return_tensors=None):
        assert return_tensors == "pt"
        return FakeInputBatch(prompt)

    def decode(self, response_ids, skip_special_tokens=True):
        self.decode_calls.append((list(response_ids), skip_special_tokens))
        return self.decode_result


class FakeModel:
    def __init__(self, *, generated_tokens=None):
        self.device = "cpu"
        self.generate_calls = []
        self.generated_tokens = (
            generated_tokens if generated_tokens is not None else [1, 2, 3, 4, 5, 6, 7]
        )

    @classmethod
    def from_pretrained(
        cls,
        model_id,
        torch_dtype="auto",
        device_map="auto",
        trust_remote_code=False,
    ):
        assert model_id == "Qwen/Qwen2.5-3B-Instruct"
        assert torch_dtype == "auto"
        assert device_map == "auto"
        assert trust_remote_code is False
        return cls()

    def to(self, device):
        self.device = device
        return self

    def generate(self, **kwargs):
        self.generate_calls.append(kwargs)
        return [self.generated_tokens]


def test_generation_settings_return_expected_generate_kwargs():
    settings = GenerationSettings(
        max_new_tokens=128,
        temperature=0.3,
        top_p=0.9,
        top_k=50,
        do_sample=True,
        repetition_penalty=1.2,
        seed=7,
    )

    kwargs = settings.to_generate_kwargs()

    assert kwargs["max_new_tokens"] == 128
    assert kwargs["temperature"] == 0.3
    assert kwargs["top_p"] == 0.9
    assert kwargs["top_k"] == 50
    assert kwargs["do_sample"] is True
    assert kwargs["repetition_penalty"] == 1.2


def test_load_and_generate_uses_chat_template(monkeypatch):
    fake_tokenizer = FakeTokenizer()
    fake_model = FakeModel()

    monkeypatch.setattr(
        qwen_adapter,
        "AutoTokenizer",
        type(
            "T",
            (),
            {"from_pretrained": staticmethod(lambda *args, **kwargs: fake_tokenizer)},
        ),
    )
    monkeypatch.setattr(
        qwen_adapter,
        "AutoModelForCausalLM",
        type(
            "M",
            (),
            {"from_pretrained": staticmethod(lambda *args, **kwargs: fake_model)},
        ),
    )

    adapter = Qwen2_5_3BAdapter()
    adapter.load()
    output = adapter.generate(
        "Summarize the report",
        system_prompt="You are a cautious analyst.",
        history=[{"role": "user", "content": "Earlier request"}],
    )

    assert output == '{"ok": true}'
    assert fake_tokenizer.messages[0]["role"] == "system"
    assert fake_tokenizer.messages[-1]["content"] == "Summarize the report"
    assert fake_model.generate_calls[0]["max_new_tokens"] == 256
    assert fake_model.generate_calls[0]["do_sample"] is False


def test_generate_json_parses_valid_json(monkeypatch):
    fake_tokenizer = FakeTokenizer()
    fake_model = FakeModel()

    monkeypatch.setattr(
        qwen_adapter,
        "AutoTokenizer",
        type(
            "T",
            (),
            {"from_pretrained": staticmethod(lambda *args, **kwargs: fake_tokenizer)},
        ),
    )
    monkeypatch.setattr(
        qwen_adapter,
        "AutoModelForCausalLM",
        type(
            "M",
            (),
            {"from_pretrained": staticmethod(lambda *args, **kwargs: fake_model)},
        ),
    )

    adapter = Qwen2_5_3BAdapter()
    adapter.load()

    assert adapter.generate_json("Return JSON") == {"ok": True}


def test_load_requires_transformers_dependency(monkeypatch):
    monkeypatch.setattr(qwen_adapter, "AutoTokenizer", None)
    monkeypatch.setattr(qwen_adapter, "AutoModelForCausalLM", None)

    with pytest.raises(RuntimeError, match="transformers must be installed"):
        Qwen2_5_3BAdapter().load()
