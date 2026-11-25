"""Cloud management backend (docs/soc.md, "Cloud management").

There is no real cloud behind it: the default provider keeps a MOCK inventory in the SOC's own
database, and every response says so (`data_source`). The optional emulated provider reads the
local Moto emulator and nothing else.
"""
