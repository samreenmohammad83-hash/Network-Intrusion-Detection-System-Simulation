from pydantic import BaseModel, Field, field_validator
from ipaddress import ip_address

class FlowIn(BaseModel):
    flow_id: str = Field(min_length=3, max_length=80)
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    protocol: str
    packet_count: float = Field(ge=0)
    byte_count: float = Field(ge=0)
    duration_seconds: float = Field(ge=0)
    connection_count: float = Field(ge=0)
    failed_connection_count: float = Field(ge=0)
    syn_count: float = Field(ge=0)
    rst_count: float = Field(ge=0)
    average_packet_size: float = Field(ge=0)
    label: str = "NORMAL"
    scenario_type: str = "UNKNOWN"

    @field_validator("source_ip","destination_ip")
    @classmethod
    def valid_ip(cls, v):
        ip_address(v)
        return v
    @field_validator("protocol")
    @classmethod
    def valid_protocol(cls, v):
        v=v.upper()
        if v not in {"TCP","UDP","ICMP"}:
            raise ValueError("protocol must be TCP, UDP, or ICMP")
        return v

class StatusUpdate(BaseModel):
    status: str
    @field_validator("status")
    @classmethod
    def valid_status(cls, v):
        if v not in {"NEW","INVESTIGATING","RESOLVED","FALSE_POSITIVE"}:
            raise ValueError("invalid status")
        return v

class NoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=2000)
