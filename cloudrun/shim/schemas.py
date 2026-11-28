"""TypeSafe-compatible (docs.typesafe.ai / api.typesafe.ai/openapi.json) request & response models.

Strict Pydantic v2 models: unknown fields are rejected, every question/answer is a
discriminated union on `type`, and FastAPI emits the same 422 `HTTPValidationError`
shape as the reference API.
"""
from __future__ import annotations

import datetime as _dt
from typing import Annotated, Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


# --------------------------------------------------------------------------- assets
class ImageAsset(_Strict):
    type: Literal["image"]
    format: Optional[Literal["png", "jpg", "jpeg"]] = None
    data_base64: Optional[str] = None
    part: Optional[str] = None  # multipart part name

    @model_validator(mode="after")
    def _one_source(self) -> "ImageAsset":
        if (self.data_base64 is None) == (self.part is None):
            raise ValueError("exactly one of `data_base64` or `part` is required")
        return self


# ------------------------------------------------------------------------ questions
# Accept the documented string form and the structured form clients send, e.g.
# {"question": "...", "examples_of_yes": ["..."]} (used by jev-cvs).
Instructions = Union[str, Dict[str, Any]]


def render_instructions(ins: Optional[Instructions]) -> str:
    if ins is None:
        return ""
    if isinstance(ins, str):
        return ins
    parts = [str(ins.get("question", ""))]
    for k, v in ins.items():
        if k == "question":
            continue
        label = k.replace("_", " ")
        if isinstance(v, list):
            parts.append(f"{label}:\n" + "\n".join(f"- {x}" for x in v))
        else:
            parts.append(f"{label}: {v}")
    return "\n".join(p for p in parts if p)


class NoulCriteria(_Strict):
    true: str
    false: str


class NoulQuestion(_Strict):
    type: Literal["noul"]
    instructions: Instructions
    criteria: Optional[NoulCriteria] = None


class ChoiceQuestion(_Strict):
    type: Literal["choice"]
    instructions: Optional[Instructions] = None
    criteria: Dict[str, str] = Field(min_length=1, max_length=255)


class ScoreQuestion(_Strict):
    type: Literal["score"]
    instructions: Optional[Instructions] = None
    criteria: List[str] = Field(min_length=1, max_length=10)


class BoxQuestion(_Strict):
    type: Literal["box"]
    instructions: Instructions


Question = Annotated[
    Union[NoulQuestion, ChoiceQuestion, ScoreQuestion, BoxQuestion],
    Field(discriminator="type"),
]

State = Union[str, Dict[str, Any], List[Any]]


class SystemOneRequest(_Strict):
    model: str = Field(min_length=1)
    state: State
    questions: Dict[str, Question] = Field(min_length=1, max_length=255)
    assets: Optional[Dict[str, ImageAsset]] = Field(default=None, min_length=1)

    @field_validator("questions")
    @classmethod
    def _keys_nonempty(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if any(not k for k in v):
            raise ValueError("question keys must be non-empty")
        return v


# -------------------------------------------------------------------------- answers
Prob = Annotated[float, Field(ge=0.0, le=1.0)]


class NoulAnswer(_Strict):
    type: Literal["noul"] = "noul"
    noul: Prob


class ChoiceAnswer(_Strict):
    type: Literal["choice"] = "choice"
    choice: str
    confidence: Prob
    probabilities: Dict[str, Prob]


class ScoreAnswer(_Strict):
    type: Literal["score"] = "score"
    score: float
    confidence: Prob
    legend: Dict[str, str]
    probabilities: Dict[str, Prob]


class BoxCoords(_Strict):
    top: Prob
    bottom: Prob
    left: Prob
    right: Prob


class BoxAnswer(_Strict):
    type: Literal["box"] = "box"
    box: BoxCoords
    confidence: Optional[Prob] = None


Answer = Annotated[
    Union[NoulAnswer, ChoiceAnswer, ScoreAnswer, BoxAnswer],
    Field(discriminator="type"),
]


class Usage(_Strict):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class SystemOneResponse(_Strict):
    model: str
    answers: Dict[str, Answer]
    usage: Usage


# --------------------------------------------------------------------------- models
class ModelMetadata(_Strict):
    name: str
    description: str
    release_date: _dt.date


class ModelMetadataList(_Strict):
    models: List[ModelMetadata]


class HTTPBadRequestError(BaseModel):
    detail: Union[str, Dict[str, Any]]
