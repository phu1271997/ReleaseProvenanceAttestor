# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *


# Minimal sanity contract. Deploy this FIRST to confirm the Studio/testnet
# environment works before deploying the full RentArbiter contract.
class Contract(gl.Contract):
    counter: u256
    last_note: str

    def __init__(self):
        self.counter = u256(0)
        self.last_note = "ready"

    @gl.public.write
    def bump(self, note: str) -> None:
        self.counter = self.counter + u256(1)
        self.last_note = note

    @gl.public.view
    def get_counter(self) -> int:
        return int(self.counter)

    @gl.public.view
    def get_note(self) -> str:
        return self.last_note
